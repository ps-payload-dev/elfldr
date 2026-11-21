/* Copyright (C) 2024 & 2025 John Törnblom
   Copyright (C) 2026 ItsJokerZz

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#define ELFLDR_IMPLEMENTATION

#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/sched.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <ps4/kernel.h>
#include <ps4/klog.h>
#include <ps4/mdbg.h>

#include "elfldr.h"
#include "log.h"
#include "mem.h"
#include <ptrace.h>

#define MB(x) (x * 0x100000)
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)                                                             \
  ((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0)           \
   | (((x) & PF_X) ? PROT_EXEC : 0))

static int
elfldr_relocate_symbol(elfldr_ctx_t *ctx, const Elf64_Shdr *shdr, size_t shnum,
                       const Elf64_Shdr *relashdr, const Elf64_Rela *rela) {
  const Elf64_Shdr *symhdr;
  const Elf64_Shdr *symstrhdr;
  const Elf64_Sym *symtab;
  const char *symstr;
  const Elf64_Sym *sym;
  unsigned long address = 0;
  unsigned int handle;
  size_t symindex = rela->r_info >> 32;

  if(relashdr->sh_link >= shnum) {
    errno = ENOEXEC;
    return -1;
  }
  symhdr = &shdr[relashdr->sh_link];
  if(symhdr->sh_type != SHT_DYNSYM || symhdr->sh_link >= shnum
     || symindex >= symhdr->sh_size / sizeof(*symtab)) {
    errno = ENOEXEC;
    return -1;
  }
  symstrhdr = &shdr[symhdr->sh_link];
  symtab = (const Elf64_Sym *)(ctx->elf + symhdr->sh_offset);
  symstr = (const char *)(ctx->elf + symstrhdr->sh_offset);
  sym = &symtab[symindex];
  if(sym->st_name >= symstrhdr->sh_size) {
    errno = ENOEXEC;
    return -1;
  }

  if(sym->st_shndx != SHN_UNDEF) {
    address = ctx->base_addr + sym->st_value - ctx->min_vaddr;
  } else {
    for(size_t i = 0; i < shnum && !address; ++i) {
      const Elf64_Shdr *dynstrhdr;
      const Elf64_Dyn *dyn;
      const char *dynstr;

      if(shdr[i].sh_type != SHT_DYNAMIC || shdr[i].sh_link >= shnum) {
        continue;
      }
      dynstrhdr = &shdr[shdr[i].sh_link];
      dynstr = (const char *)(ctx->elf + dynstrhdr->sh_offset);
      dyn = (const Elf64_Dyn *)(ctx->elf + shdr[i].sh_offset);
      for(size_t j = 0; j < shdr[i].sh_size / sizeof(*dyn); ++j) {
        if(dyn[j].d_tag != DT_NEEDED
           || dyn[j].d_un.d_val >= dynstrhdr->sh_size) {
          continue;
        }
        if(kernel_dynlib_handle(ctx->pid, dynstr + dyn[j].d_un.d_val,
                                &handle)) {
          continue;
        }
        address = kernel_dynlib_dlsym(ctx->pid, handle, symstr + sym->st_name);
        if(!address
           && (!strcmp(symstr + sym->st_name, "scePadSetVibrationMode")
               || !strcmp(symstr + sym->st_name,
                          "sceVideoOutSetBufferAttribute2")
               || !strcmp(symstr + sym->st_name,
                          "sceVideoOutRegisterBuffers2"))) {
          LOG_PRINTF("elfldr: symbol %s absent in %s handle=%u\n",
                     symstr + sym->st_name, dynstr + dyn[j].d_un.d_val,
                     handle);
        }
        if(address) {
          break;
        }
      }
    }
  }

  if(!address || rela->r_offset < ctx->min_vaddr
     || ctx->base_size < sizeof(address)
     || rela->r_offset - ctx->min_vaddr > ctx->base_size - sizeof(address)) {
    LOG_PRINTF("elfldr_load: cannot resolve symbol %s\n",
               symstr + sym->st_name);
    errno = ENOENT;
    return -1;
  }

  unsigned long *location
      = (unsigned long *)((uint8_t *)ctx->base_mirror + rela->r_offset
                          - ctx->min_vaddr);
  switch(rela->r_info & 0xfffffffful) {
    case R_X86_64_64:
      *location = address + rela->r_addend;
      break;
    case R_X86_64_GLOB_DAT:
    case R_X86_64_JMP_SLOT:
      *location = address;
      break;
    default:
      errno = ENOTSUP;
      return -1;
  }

  return 0;
}

static int
elfldr_load_needed_modules(pid_t pid, const uint8_t *elf) {
  static const char *const libdirs[]
      = { "/system/priv/lib", "/system/common/lib", "/system_ex/priv_ex/lib",
          "/system_ex/common_ex/lib" };
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
  const Elf64_Shdr *shdr = (const Elf64_Shdr *)(elf + ehdr->e_shoff);
  intptr_t load_start;
  intptr_t load_sysmodule;
  unsigned int sysmodule_handle;

  load_start = pt_resolve(pid, "sceKernelLoadStartModule");
  if(!load_start) {
    LOG_PUTS("elfldr: cannot resolve sceKernelLoadStartModule");
    return -1;
  }
  load_sysmodule = 0;
  if(kernel_dynlib_handle(pid, "libSceSysmodule.sprx", &sysmodule_handle)) {
    const char sysmodule_path[] = "/system/common/lib/libSceSysmodule.sprx";
    intptr_t remote_path = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if(remote_path != -1
       && !pt_copyin(pid, sysmodule_path, remote_path,
                     sizeof(sysmodule_path))) {
      uint64_t args[6] = { (uint64_t)remote_path };
      intptr_t result = -1;
      int call_error = pt_call(pid, load_start, args, &result);
      if(call_error || (int32_t)result <= 0) {
        LOG_PRINTF(
            "elfldr: load libSceSysmodule.sprx failed result=0x%08x call=%d\n",
            (unsigned int)(int32_t)result, call_error);
      }
      pt_munmap(pid, remote_path, PAGE_SIZE);
    } else {
      LOG_PUTS("elfldr: cannot allocate path for libSceSysmodule.sprx");
      if(remote_path != -1)
        pt_munmap(pid, remote_path, PAGE_SIZE);
    }
  }
  if(!kernel_dynlib_handle(pid, "libSceSysmodule.sprx", &sysmodule_handle)) {
    load_sysmodule = kernel_dynlib_dlsym(pid, sysmodule_handle,
                                         "sceSysmoduleLoadModuleInternal");
  }
  if(!load_sysmodule) {
    LOG_PUTS("elfldr: cannot resolve sceSysmoduleLoadModuleInternal");
  }

  for(size_t i = 0; i < ehdr->e_shnum; ++i) {
    const Elf64_Shdr *strhdr;
    const Elf64_Dyn *dyn;
    const char *strtab;

    if(shdr[i].sh_type != SHT_DYNAMIC || shdr[i].sh_link >= ehdr->e_shnum) {
      continue;
    }
    strhdr = &shdr[shdr[i].sh_link];
    strtab = (const char *)(elf + strhdr->sh_offset);
    dyn = (const Elf64_Dyn *)(elf + shdr[i].sh_offset);

    for(size_t j = 0; j < shdr[i].sh_size / sizeof(*dyn); ++j) {
      unsigned int handle;
      int loaded = 0;

      if(dyn[j].d_tag != DT_NEEDED || dyn[j].d_un.d_val >= strhdr->sh_size) {
        continue;
      }
      const char *name = strtab + dyn[j].d_un.d_val;
      if(!kernel_dynlib_handle(pid, name, &handle)) {
        continue;
      }

      unsigned int sysmodule = 0;
      if(!strcmp(name, "libSceSystemService.sprx"))
        sysmodule = 0x80000010;
      else if(!strcmp(name, "libSceUserService.sprx"))
        sysmodule = 0x80000011;
      else if(!strcmp(name, "libSceNet.sprx"))
        sysmodule = 0x8000001c;
      else if(!strcmp(name, "libSceAudioOut.sprx"))
        sysmodule = 0x80000001;
      else if(!strcmp(name, "libScePad.sprx"))
        sysmodule = 0x80000024;
      else if(!strcmp(name, "libSceVideoOut.sprx"))
        sysmodule = 0x80000022;
      if(sysmodule && load_sysmodule) {
        uint64_t sysmodule_args[6] = { sysmodule };
        intptr_t sysmodule_result = -1;
        int call_error
            = pt_call(pid, load_sysmodule, sysmodule_args, &sysmodule_result);
        if(call_error || (int32_t)sysmodule_result < 0) {
          LOG_PRINTF(
              "elfldr: sysmodule %s id=0x%08x failed result=0x%08x call=%d\n",
              name, sysmodule, (unsigned int)(int32_t)sysmodule_result,
              call_error);
        }
      }

      for(size_t d = 0; d < sizeof(libdirs) / sizeof(libdirs[0]); ++d) {
        char path[PATH_MAX];
        intptr_t remote_path;
        intptr_t result = -1;
        uint64_t args[6] = { 0 };

        if(snprintf(path, sizeof(path), "%s/%s", libdirs[d], name)
           >= sizeof(path)) {
          errno = ENAMETOOLONG;
          return -1;
        }
        if(access(path, F_OK)) {
          continue;
        }
        remote_path = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(remote_path == -1) {
          LOG_PT_PERROR(pid, "map module path");
          return -1;
        }
        if(pt_copyin(pid, path, remote_path, strlen(path) + 1)) {
          LOG_PT_PERROR(pid, "copy module path");
          pt_munmap(pid, remote_path, PAGE_SIZE);
          return -1;
        }
        args[0] = (uint64_t)remote_path;
        int call_error = pt_call(pid, load_start, args, &result);
        pt_munmap(pid, remote_path, PAGE_SIZE);
        if(!call_error && (int32_t)result > 0) {
          loaded = 1;
          break;
        }
        LOG_PRINTF("elfldr: load dependency %s from %s failed result=0x%08x\n",
                   name, path, (unsigned int)(int32_t)result);
      }
      if(!loaded) {
        LOG_PRINTF("elfldr: unable to load dependency %s\n", name);
        return -1;
      }
    }
  }

  return 0;
}

intptr_t
elfldr_load(pid_t pid, const uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
  const Elf64_Phdr *phdr = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
  const Elf64_Shdr *shdr = (const Elf64_Shdr *)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = { .elf = elf, .pid = pid };

  size_t min_vaddr = SIZE_MAX;
  size_t max_vaddr = 0;

  int error = 0;

  if(!ehdr->e_phnum) {
    LOG_PUTS("elfldr_load: ELF has no program headers");
    return 0;
  }

  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz) {
      continue;
    }
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  if(min_vaddr == SIZE_MAX || max_vaddr > SIZE_MAX - (PAGE_SIZE - 1)) {
    LOG_PUTS("elfldr_load: invalid loadable segment range");
    return 0;
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.min_vaddr = min_vaddr;
  ctx.base_size = max_vaddr - ctx.min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    LOG_PUTS("elfldr_load: ELF type not supported");
    return 0;
  }

  if(!(ctx.base_mirror = mem_alloc(ctx.base_size))) {
    LOG_PERROR("mem_alloc");
    return 0;
  }

  if((ctx.base_addr
      = pt_mmap(pid, ctx.base_addr, ctx.base_size, prot, flags, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    mem_free(ctx.base_mirror);
    return 0;
  }

  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
      case PT_LOAD:
        error = data_load(&ctx, &phdr[i]);
        break;
    }
  }

  for(int i = 0; i < ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    const Elf64_Rela *rela = (const Elf64_Rela *)(elf + shdr[i].sh_offset);
    for(int j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++) {
      switch(rela[j].r_info & 0xffffffffl) {
        case R_X86_64_RELATIVE:
          error = r_relative(&ctx, &rela[j]);
          break;
        case R_X86_64_64:
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JMP_SLOT:
          error = elfldr_relocate_symbol(&ctx, shdr, ehdr->e_shnum, &shdr[i],
                                         &rela[j]);
          break;
      }
    }
  }

  if(mdbg_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("mdbg_copyin");
    error = 1;
  }

  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }
    uintptr_t segment_start = TRUNC_PG(phdr[i].p_vaddr);
    uintptr_t segment_end = ROUND_PG(phdr[i].p_vaddr + phdr[i].p_memsz);
    intptr_t address = ctx.base_addr + segment_start - ctx.min_vaddr;
    if(pt_mprotect(pid, address, segment_end - segment_start,
                   PFLAGS(phdr[i].p_flags))) {
      LOG_PT_PERROR(pid, "pt_mprotect");
      error = 1;
    }
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    LOG_PT_PERROR(pid, "pt_msync");
    error = 1;
  }

  mem_free(ctx.base_mirror);

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry - ctx.min_vaddr;
}

static int
elfldr_prepare_exec(pid_t pid, const uint8_t *elf) {
  intptr_t entry;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    return -1;
  }

  if(elfldr_load_needed_modules(pid, elf)) {
    LOG_PERROR("elfldr_load_needed_modules");
    return -1;
  }
  if(!(entry = elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    return -1;
  }

  r.r_rsp &= ~0xfl;
  r.r_rsp -= 8;
  r.r_rip = entry;

  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  return 0;
}

int
elfldr_raise_privileges(pid_t pid) {
  unsigned char caps[16] = { 0 };

  if(kernel_set_proc_rootdir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    LOG_PUTS("kernel_set_proc_rootdir failed");
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, KERNEL_ADDRESS_ROOTVNODE)) {
    LOG_PUTS("kernel_set_proc_jaildir failed");
    return -1;
  }
  if(kernel_set_ucred_prison(pid, KERNEL_ADDRESS_PRISON0)) {
    LOG_PUTS("kernel_set_ucred_prison failed");
    return -1;
  }

  if(kernel_set_ucred_uid(pid, 0)) {
    LOG_PUTS("kernel_set_ucred_uid failed");
    return -1;
  }

  if(kernel_get_ucred_caps(pid, caps)) {
    return -1;
  }
  caps[5] = 0x1c;
  caps[7] = 0x40;
  caps[15] |= 0x40;
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }
  if(kernel_set_ucred_authid(pid, 0x3801000000000013l)) {
    LOG_PUTS("kernel_set_ucred_authid failed");
    return -1;
  }

  return 0;
}

int
elfldr_exec(pid_t pid, int stdio, const uint8_t *elf) {
  int error = 0;

  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(stdio > 0) {
    stdio = pt_rdup(pid, getpid(), stdio);

    pt_close(pid, STDERR_FILENO);
    pt_close(pid, STDOUT_FILENO);
    pt_close(pid, STDIN_FILENO);

    pt_dup2(pid, stdio, STDIN_FILENO);
    pt_dup2(pid, stdio, STDOUT_FILENO);
    pt_dup2(pid, stdio, STDERR_FILENO);

    pt_close(pid, stdio);
  }

  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }

  if(pt_detach(pid, 0)) {
    LOG_PERROR("pt_detach");
    error = -1;
  }

  return error;
}

int
elfldr_set_heap_size(pid_t pid, ssize_t size) {
  intptr_t sceLibcHeapExtendedAlloc;
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  intptr_t buf;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }
  if(pt_dynlib_get_proc_param(pid, buf, buf + 0x100)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }
  if(!(sceProcParam = mdbg_getlong(pid, buf))) {
    LOG_PERROR("mdbg_getlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_copyout(pid, sceProcParam + 56, &sceLibcParam,
                  sizeof(sceLibcParam))) {
    LOG_PERROR("mdbg_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_copyout(pid, sceLibcParam + 16, &sceLibcHeapSize,
                  sizeof(sceLibcHeapSize))) {
    LOG_PERROR("mdbg_copyout");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_setint(pid, sceLibcHeapSize, size)) {
    LOG_PERROR("mdbg_setint");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(size != -1) {
    pt_munmap(pid, buf, PAGE_SIZE);
    return 0;
  }

  sceLibcHeapExtendedAlloc = buf;
  if(mdbg_setlong(pid, sceLibcParam + 32, sceLibcHeapExtendedAlloc)) {
    LOG_PERROR("mdbg_setlong");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  if(mdbg_setint(pid, sceLibcHeapExtendedAlloc, 1)) {
    LOG_PERROR("mdbg_setint");
    pt_munmap(pid, buf, PAGE_SIZE);
    return -1;
  }

  return 0;
}

int
elfldr_set_procname(pid_t pid, const char *name) {
  intptr_t buf;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }

  mdbg_copyin(pid, name, buf, strlen(name) + 1);

  pt_syscall(pid, SYS_thr_set_name, (uint64_t)-1, (uint64_t)buf, 0ULL, 0ULL,
             0ULL, 0ULL);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}

int
elfldr_set_cwd(pid_t pid, const char *cwd) {
  intptr_t buf;
  int err = 0;

  if(!cwd) {
    cwd = "/";
  }
  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }
  if(pt_copyin(pid, cwd, buf, strlen(cwd) + 1)) {
    LOG_PERROR("pt_copyin");
    err = -1;
  } else if(pt_syscall(pid, SYS_chdir, (uint64_t)buf, 0ULL, 0ULL, 0ULL, 0ULL,
                       0ULL)
            < 0) {
    LOG_PT_PERROR(pid, "chdir");
    err = -1;
  }
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);
  return err;
}

int
elfldr_set_environ(pid_t pid, char *const envp[]) {
  size_t size = sizeof(char *);
  intptr_t environ_addr;
  intptr_t envp_addr;
  intptr_t pos;
  int n = 0;

  if(!envp || !envp[0]) {
    return 0;
  }
  while(envp[n]) {
    size += sizeof(uintptr_t) + strlen(envp[n]) + 1;
    n++;
  }
  size = ROUND_PG(size);
  if((envp_addr = pt_mmap(pid, 0, size, PROT_WRITE | PROT_READ,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return -1;
  }
  pos = envp_addr + ((n + 1) * sizeof(uintptr_t));
  for(int i = 0; i < n; i++) {
    size_t len = strlen(envp[i]) + 1;
    if(pt_copyin(pid, envp[i], pos, len)
       || pt_setlong(pid, envp_addr + (i * sizeof(uintptr_t)), pos)) {
      LOG_PT_PERROR(pid, "copy environment");
      pt_munmap(pid, envp_addr, size);
      return -1;
    }
    pos += len;
  }
  if(pt_setlong(pid, envp_addr + (n * sizeof(uintptr_t)), 0)) {
    LOG_PT_PERROR(pid, "terminate environment");
    pt_munmap(pid, envp_addr, size);
    return -1;
  }
  if(!(environ_addr = pt_resolve(pid, "+2thxYZ4syk"))) {
    LOG_PERROR("pt_resolve environ");
    pt_munmap(pid, envp_addr, size);
    return -1;
  }
  if(pt_setlong(pid, environ_addr, envp_addr)) {
    LOG_PT_PERROR(pid, "set environ");
    pt_munmap(pid, envp_addr, size);
    return -1;
  }
  return 0;
}

int
elfldr_set_stdio(pid_t pid, int stdio) {
  int err = 0;
  if(stdio < 0) {
    return 0;
  }
  stdio = pt_rdup(pid, getpid(), stdio);
  if(stdio < 0 || pt_dup2(pid, stdio, STDOUT_FILENO) < 0
     || pt_dup2(pid, stdio, STDERR_FILENO) < 0 || pt_close(pid, stdio) < 0) {
    LOG_PT_PERROR(pid, "redirect stdio");
    err = -1;
  }
  return err;
}

static int
elfldr_rfork_entry(void *argv) {
  const char *SceSpZeroConf = "/system/vsh/app/NPXS21016/eboot.bin";
  struct sched_param sp;

  if(syscall(0x23b, 0)) {
    LOG_PERROR("sys_budget_set");
    return 0;
  }

  if(open("/dev/deci_stdin", O_RDONLY) < 0) {
    LOG_PERROR("open");
    return 0;
  }
  if(open("/dev/deci_stdout", O_WRONLY) < 0) {
    LOG_PERROR("open");
    return 0;
  }
  if(open("/dev/deci_stderr", O_WRONLY) < 0) {
    LOG_PERROR("open");
    return 0;
  }

  sp.sched_priority = sched_get_priority_min(SCHED_RR);
  if(sched_setscheduler(0, SCHED_RR, &sp)) {
    LOG_PERROR("sched_setscheduler");
  }

  execve(SceSpZeroConf, argv, 0);

  LOG_PERROR("execve");
  return 0;
}

pid_t
elfldr_spawn(const char *cwd, int stdio, char *const argv[],
             char *const envp[], const uint8_t *elf, size_t elf_size) {
  struct kevent evt;
  void *stack;
  pid_t pid;
  int kq;

  if(elfldr_sanity_check(elf, elf_size)) {
    errno = ENOEXEC;
    return -1;
  }
#if defined(__ORBIS__)
  if(patch_ps4_ptrace()) {
    LOG_PERROR("patch_ps4_ptrace before spawn");
    return -1;
  }
#endif

  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }

  if(!(stack = mem_alloc(MB(2)))) {
    LOG_PERROR("malloc");
    close(kq);
    return -1;
  }

  if((pid = rfork_thread(RFPROC | RFCFDG | RFMEM, stack + MB(2),
                         elfldr_rfork_entry, (void *)argv))
     < 0) {
    LOG_PERROR("rfork_thread");
    mem_free(stack);
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    kill(pid, SIGKILL);
    while(waitpid(pid, 0, 0) < 0 && errno == EINTR) {
    }
    mem_free(stack);
    close(kq);
    return -1;
  }

  usleep(20000);

  unsigned int attach_attempt = 0;
  unsigned int attach_timeouts = 0;
  while(pt_attach(pid) == -1) {
    if(errno == EBUSY && ++attach_attempt < 1000) {
      continue;
    }
    if(errno == ETIMEDOUT && ++attach_timeouts < 3) {
      usleep(50000);
      continue;
    }
    LOG_PRINTF("elfldr_spawn: PT_ATTACH failed pid=%d attempt=%u errno=%d\n",
               pid, attach_attempt + 1, errno);
    LOG_PERROR("pt_attach after exec");
    kill(pid, SIGKILL);
    while(waitpid(pid, 0, 0) < 0 && errno == EINTR) {
    }
    mem_free(stack);
    close(kq);
    return -1;
  }
  if(elfldr_raise_privileges(pid)) {
    LOG_PERROR("elfldr_raise_privileges");
    pt_detach(pid, SIGKILL);
    mem_free(stack);
    close(kq);
    return -1;
  }

  mem_free(stack);
  close(kq);

  if(kernel_get_fw_version() < 0x14020000
     && pt_dynlib_process_needed_and_relocate(pid)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(elfldr_set_heap_size(pid, -1)) {
    LOG_PT_PERROR(pid, "pt_dynlib_process_needed_and_relocate");
  }

  if(elfldr_set_procname(pid, argv && argv[0] ? argv[0] : "Payload")) {
    LOG_PRINTF("elfldr_spawn: set process name failed pid=%d errno=%d\n", pid,
               errno);
  }
  if(elfldr_set_environ(pid, envp)) {
    LOG_PRINTF("elfldr_spawn: set environment failed pid=%d errno=%d\n", pid,
               errno);
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(elfldr_set_cwd(pid, cwd)) {
    LOG_PRINTF("elfldr_spawn: set cwd failed pid=%d errno=%d\n", pid, errno);
    pt_detach(pid, SIGKILL);
    return -1;
  }
  if(elfldr_exec(pid, stdio, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}

pid_t
elfldr_spawn_legacy(int stdio, char *const argv[], const uint8_t *elf,
                    size_t elf_size) {
  return elfldr_spawn("/", stdio, argv, NULL, elf, elf_size);
}
