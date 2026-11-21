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
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "log.h"
#include "mem.h"
#include <ptrace.h>

#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)                                                             \
  ((((x) & PF_R) ? PROT_READ : 0) | (((x) & PF_W) ? PROT_WRITE : 0)           \
   | (((x) & PF_X) ? PROT_EXEC : 0))

static const char *SceSpZeroConf = "/system/vsh/app/NPXS40112/eboot.bin";

intptr_t
elfldr_load(pid_t pid, const uint8_t *elf) {
  const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf;
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
  int prot = PROT_READ | PROT_WRITE;
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
      }
    }
  }

  if(pt_copyin(ctx.pid, ctx.base_mirror, ctx.base_addr, ctx.base_size)) {
    LOG_PERROR("pt_copyin");
    error = 1;
  }

  for(int i = 0; i < ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    uintptr_t segment_start = TRUNC_PG(phdr[i].p_vaddr);
    uintptr_t segment_end = ROUND_PG(phdr[i].p_vaddr + phdr[i].p_memsz);
    intptr_t address = ctx.base_addr + segment_start - ctx.min_vaddr;
    if(phdr[i].p_flags & PF_X) {
      if(kernel_mprotect(pid, address, segment_end - segment_start,
                         PFLAGS(phdr[i].p_flags))) {
        LOG_PERROR("kernel_mprotect");
        error = 1;
      }
    } else {
      if(pt_mprotect(pid, address, segment_end - segment_start,
                     PFLAGS(phdr[i].p_flags))) {
        LOG_PT_PERROR(pid, "pt_mprotect");
        error = 1;
      }
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

intptr_t
elfldr_payload_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf = pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))
     == -1) {
    LOG_PT_PERROR(pid, "pt_mmap");
    return 0;
  }

  if((master_sock = pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    LOG_PT_PERROR(pid, "pt_socket");
    return 0;
  }

  pt_setint(pid, buf + 0x00, 20);
  pt_setint(pid, buf + 0x04, IPPROTO_IPV6);
  pt_setint(pid, buf + 0x08, IPV6_TCLASS);
  pt_setint(pid, buf + 0x0c, 0);
  pt_setint(pid, buf + 0x10, 0);
  pt_setint(pid, buf + 0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf,
                   24)) {
    LOG_PT_PERROR(pid, "pt_setsockopt");
    return 0;
  }

  if((victim_sock = pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    LOG_PT_PERROR(pid, "pt_socket");
    return 0;
  }

  pt_setint(pid, buf + 0x00, 0);
  pt_setint(pid, buf + 0x04, 0);
  pt_setint(pid, buf + 0x08, 0);
  pt_setint(pid, buf + 0x0c, 0);
  pt_setint(pid, buf + 0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    LOG_PT_PERROR(pid, "pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    LOG_PUTS("kernel_overlap_sockets failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    LOG_PT_PERROR(pid, "pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf + 4);

  intptr_t args = buf;
  intptr_t rwpipe = buf + 0x100;
  intptr_t rwpair = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;
  intptr_t getpid = pt_resolve(pid, "HoLVWNanBBc");

  pt_setlong(pid, args + 0x00, getpid);
  pt_setlong(pid, args + 0x08, rwpipe);
  pt_setlong(pid, args + 0x10, rwpair);
  pt_setlong(pid, args + 0x18, kpipe_addr);
  pt_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  pt_setlong(pid, args + 0x28, payloadout);
  pt_setint(pid, rwpipe + 0, pipe0);
  pt_setint(pid, rwpipe + 4, pipe1);
  pt_setint(pid, rwpair + 0, master_sock);
  pt_setint(pid, rwpair + 4, victim_sock);
  pt_setint(pid, payloadout, 0);

  return args;
}

static int
elfldr_prepare_exec(pid_t pid, const uint8_t *elf) {
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    LOG_PERROR("pt_getregs");
    return -1;
  }

  if(!(entry = elfldr_load(pid, elf))) {
    LOG_PUTS("elfldr_load failed");
    return -1;
  }

  if(!(args = elfldr_payload_args(pid))) {
    LOG_PUTS("elfldr_payload_args failed");
    return -1;
  }

  pt_setlong(pid, r.r_rsp - 8, r.r_rip);
  r.r_rsp -= 8;
  r.r_rip = entry;
  r.r_rdi = args;

  if(pt_setregs(pid, &r)) {
    LOG_PERROR("pt_setregs");
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

  pt_copyin(pid, name, buf, strlen(name) + 1);
  pt_syscall(pid, SYS_thr_set_name, (uint64_t)-1, (uint64_t)buf, 0ULL, 0ULL,
             0ULL, 0ULL);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}

int
elfldr_raise_privileges(pid_t pid) {
  static const uint8_t caps[16]
      = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  intptr_t vnode;

  if(!(vnode = kernel_get_root_vnode())) {
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }

  return 0;
}

int
elfldr_exec(pid_t pid, int stdio, const uint8_t *elf) {
  uint8_t caps[16];
  intptr_t jaildir;
  intptr_t rootdir;
  uint64_t authid;
  int error = 0;

  jaildir = kernel_get_proc_jaildir(pid);
  if(!(rootdir = kernel_get_proc_rootdir(pid))) {
    LOG_PUTS("kernel_get_proc_rootdir failed");
    pt_detach(pid, 0);
    return -1;
  }
  if(kernel_get_ucred_caps(pid, caps)) {
    LOG_PUTS("kernel_get_ucred_caps failed");
    pt_detach(pid, 0);
    return -1;
  }
  if(!(authid = kernel_get_ucred_authid(pid))) {
    LOG_PUTS("kernel_get_ucred_authid failed");
    pt_detach(pid, 0);
    return -1;
  }

  if(elfldr_raise_privileges(pid)) {
    LOG_PUTS("Unable to raise privileges");
    pt_detach(pid, 0);
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

  if(kernel_set_proc_jaildir(pid, jaildir)) {
    LOG_PUTS("kernel_set_proc_jaildir failed");
    error = -1;
  }
  if(kernel_set_proc_rootdir(pid, rootdir)) {
    LOG_PUTS("kernel_set_proc_rootdir failed");
    error = -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    LOG_PUTS("kernel_set_ucred_caps failed");
    error = -1;
  }
  if(kernel_set_ucred_authid(pid, authid)) {
    LOG_PUTS("kernel_set_ucred_authid failed");
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
  intptr_t sceLibcHeapSize;
  intptr_t sceLibcParam;
  intptr_t sceProcParam;
  intptr_t Need_sceLibc;

  if(!(sceProcParam = pt_sceKernelGetProcParam(pid))) {
    LOG_PT_PERROR(pid, "pt_sceKernelGetProcParam");
    return -1;
  }

  if(pt_copyout(pid, sceProcParam + 56, &sceLibcParam, sizeof(sceLibcParam))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  if(pt_copyout(pid, sceLibcParam + 16, &sceLibcHeapSize,
                sizeof(sceLibcHeapSize))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  if(pt_setlong(pid, sceLibcHeapSize, size)) {
    LOG_PERROR("pt_setlong");
    return -1;
  }

  if(size != -1) {
    return 0;
  }

  if(pt_copyout(pid, sceLibcParam + 72, &Need_sceLibc, sizeof(Need_sceLibc))) {
    LOG_PERROR("pt_copyout");
    return -1;
  }

  return pt_setlong(pid, sceLibcParam + 32, Need_sceLibc);
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
sys_budget_set(long budget) {
  return __syscall(0x23b, budget);
}

static int __attribute__((force_align_arg_pointer))
elfldr_rfork_entry(void *argv) {
  if(sys_budget_set(0)) {
    LOG_PERROR("sys_budget_set");
    return -1;
  }
  if(open("/dev/deci_stdin", O_RDONLY) < 0) {
    LOG_PERROR("open");
    return -1;
  }
  if(open("/dev/deci_stdout", O_WRONLY) < 0) {
    LOG_PERROR("open");
    return -1;
  }
  if(open("/dev/deci_stderr", O_WRONLY) < 0) {
    LOG_PERROR("open");
    return -1;
  }

  if(ptrace(PT_TRACE_ME, 0, 0, 0)) {
    LOG_PERROR("ptrace");
    return -1;
  }

  execve(SceSpZeroConf, argv, 0);
  LOG_PERROR("execve");
  return -1;
}

pid_t
elfldr_spawn(const char *cwd, int stdio, char *const argv[],
             char *const envp[], const uint8_t *elf, size_t payload_size) {
  intptr_t libkernel_entry;
  off_t need_reloc_offset;
  intptr_t eboot_entry;
  off_t main_offset;
  struct kevent evt;
  void *stack;
  pid_t pid;
  int kq;

  if(elfldr_sanity_check(elf, payload_size)) {
    errno = ENOEXEC;
    return -1;
  }

  if((kq = kqueue()) < 0) {
    LOG_PERROR("kqueue");
    return -1;
  }

  if(!(stack = mem_alloc(PAGE_SIZE))) {
    LOG_PERROR("malloc");
    close(kq);
    return -1;
  }

  if((pid = rfork_thread(RFPROC | RFCFDG | RFMEM, stack + PAGE_SIZE - 8,
                         elfldr_rfork_entry, (void *)argv))
     < 0) {
    LOG_PERROR("rfork_thread");
    mem_free(stack);
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC, 0, 0);
  if(kevent(kq, &evt, 1, &evt, 1, 0) < 0) {
    LOG_PERROR("kevent");
    kill(pid, SIGKILL);
    while(waitpid(pid, 0, 0) < 0 && errno == EINTR) {
    }
    mem_free(stack);
    close(kq);
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    LOG_PERROR("waitpid");
    kill(pid, SIGKILL);
    while(waitpid(pid, 0, 0) < 0 && errno == EINTR) {
    }
    mem_free(stack);
    close(kq);
    return -1;
  }

  mem_free(stack);
  close(kq);

  if(!(libkernel_entry = kernel_dynlib_entry_addr(pid, 1))) {
    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(!(eboot_entry = kernel_dynlib_entry_addr(pid, 0))) {
    LOG_PUTS("kernel_dynlib_entry_addr failed");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  if(kernel_get_fw_version() < 0x14000000) {
    need_reloc_offset = 15;
    main_offset = 58;
  } else {
    need_reloc_offset = 15;
    main_offset = 63;
  }

  if(pt_breakat(pid, libkernel_entry + need_reloc_offset)) {
    LOG_PERROR("pt_breakat");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  elfldr_set_heap_size(pid, -1);

  if(pt_breakat(pid, eboot_entry + main_offset)) {
    LOG_PERROR("pt_breakat");
    pt_detach(pid, SIGKILL);
    return -1;
  }

  elfldr_set_procname(pid, argv && argv[0] ? argv[0] : "Payload");
  if(elfldr_set_environ(pid, envp) || elfldr_set_cwd(pid, cwd)) {
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
