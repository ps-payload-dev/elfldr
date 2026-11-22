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

#include <elf.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/sysctl.h>

#include "elfldr.h"
#include "log.h"
#include "mem.h"

static int
elfldr_range(uint64_t offset, uint64_t length, size_t size) {
  return offset <= size && length <= size - (size_t)offset;
}

int
r_relative(elfldr_ctx_t *ctx, const Elf64_Rela *rela) {
  intptr_t *loc;
  intptr_t val;

  if(rela->r_offset < ctx->min_vaddr || ctx->base_size < sizeof(*loc)
     || rela->r_offset - ctx->min_vaddr > ctx->base_size - sizeof(*loc)) {
    return -1;
  }

  loc = (intptr_t *)((uint8_t *)ctx->base_mirror + rela->r_offset
                     - ctx->min_vaddr);
  val = ctx->base_addr - ctx->min_vaddr + rela->r_addend;
  *loc = val;

  return 0;
}

int
data_load(elfldr_ctx_t *ctx, const Elf64_Phdr *phdr) {
  uint64_t offset;

  if(!phdr->p_memsz || !phdr->p_filesz) {
    return 0;
  }
  if(phdr->p_filesz > phdr->p_memsz || phdr->p_vaddr < ctx->min_vaddr) {
    return -1;
  }

  offset = phdr->p_vaddr - ctx->min_vaddr;
  if(offset > ctx->base_size || phdr->p_filesz > ctx->base_size - offset) {
    return -1;
  }

  memcpy((uint8_t *)ctx->base_mirror + offset, ctx->elf + phdr->p_offset,
         phdr->p_filesz);
  return 0;
}

int
elfldr_sanity_check(const uint8_t *elf, size_t elf_size) {
  const Elf64_Ehdr *ehdr;
  const Elf64_Phdr *phdr;
  const Elf64_Shdr *shdr;

  if(!elf || elf_size < sizeof(Elf64_Ehdr)) {
    return -1;
  }

  ehdr = (const Elf64_Ehdr *)elf;
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E'
     || ehdr->e_ident[2] != 'L' || ehdr->e_ident[3] != 'F'
     || ehdr->e_ident[EI_CLASS] != ELFCLASS64
     || ehdr->e_ident[EI_DATA] != ELFDATA2LSB || ehdr->e_machine != EM_X86_64
     || ehdr->e_version != EV_CURRENT || ehdr->e_ehsize != sizeof(Elf64_Ehdr)
     || (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
     || !ehdr->e_phnum) {
    return -1;
  }

  uint64_t phdr_size = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
  if(ehdr->e_phentsize != sizeof(Elf64_Phdr)
     || !elfldr_range(ehdr->e_phoff, phdr_size, elf_size)) {
    return -1;
  }

  phdr = (const Elf64_Phdr *)(elf + ehdr->e_phoff);
  int has_load_segment = 0;
  for(int i = 0; i < ehdr->e_phnum; i++) {
    if(!elfldr_range(phdr[i].p_offset, phdr[i].p_filesz, elf_size)) {
      return -1;
    }
    if(phdr[i].p_type == PT_LOAD) {
      if(phdr[i].p_filesz > phdr[i].p_memsz
         || phdr[i].p_memsz > UINT64_MAX - phdr[i].p_vaddr) {
        return -1;
      }
      has_load_segment |= phdr[i].p_memsz != 0;
    }
  }
  if(!has_load_segment) {
    return -1;
  }

  if(ehdr->e_shnum) {
    uint64_t shdr_size = (uint64_t)ehdr->e_shnum * sizeof(Elf64_Shdr);
    if(ehdr->e_shentsize != sizeof(Elf64_Shdr)
       || !elfldr_range(ehdr->e_shoff, shdr_size, elf_size)) {
      return -1;
    }

    shdr = (const Elf64_Shdr *)(elf + ehdr->e_shoff);
    for(int i = 0; i < ehdr->e_shnum; i++) {
      if(shdr[i].sh_type != SHT_NOBITS
         && !elfldr_range(shdr[i].sh_offset, shdr[i].sh_size, elf_size)) {
        return -1;
      }
    }
  }

  return 0;
}

int
elfldr_read(int fd, uint8_t **elf, size_t *elf_size) {
  const Elf64_Phdr *phdr;
  const Elf64_Shdr *shdr;
  Elf64_Ehdr ehdr;
  uint8_t *buf;
  uint64_t table_end = sizeof(ehdr);
  uint64_t file_end;
  size_t size;
  size_t rem;

  if(recv(fd, &ehdr, sizeof(ehdr), MSG_WAITALL) != sizeof(ehdr)) {
    return -1;
  }

  if(ehdr.e_ident[0] != 0x7f || ehdr.e_ident[1] != 'E'
     || ehdr.e_ident[2] != 'L' || ehdr.e_ident[3] != 'F'
     || ehdr.e_ident[EI_CLASS] != ELFCLASS64
     || ehdr.e_ident[EI_DATA] != ELFDATA2LSB
     || (ehdr.e_phnum && ehdr.e_phentsize != sizeof(Elf64_Phdr))
     || (ehdr.e_shnum && ehdr.e_shentsize != sizeof(Elf64_Shdr))) {
    errno = ENOEXEC;
    return -1;
  }

  if(ehdr.e_phnum) {
    uint64_t phdr_size = (uint64_t)ehdr.e_phnum * sizeof(Elf64_Phdr);
    if(ehdr.e_phoff > UINT64_MAX - phdr_size) {
      errno = ENOEXEC;
      return -1;
    }
    uint64_t end = ehdr.e_phoff + phdr_size;
    if(end > table_end) {
      table_end = end;
    }
  }
  if(ehdr.e_shnum) {
    uint64_t shdr_size = (uint64_t)ehdr.e_shnum * sizeof(Elf64_Shdr);
    if(ehdr.e_shoff > UINT64_MAX - shdr_size) {
      errno = ENOEXEC;
      return -1;
    }
    uint64_t end = ehdr.e_shoff + shdr_size;
    if(end > table_end) {
      table_end = end;
    }
  }
  if(table_end > SIZE_MAX) {
    errno = ENOEXEC;
    return -1;
  }

  size = table_end;
  if(!(buf = mem_alloc(size))) {
    return -1;
  }

  memcpy(buf, &ehdr, sizeof(ehdr));
  rem = size - sizeof(ehdr);
  if(recv(fd, buf + sizeof(ehdr), rem, MSG_WAITALL) != rem) {
    mem_free(buf);
    return -1;
  }

  file_end = table_end;
  if(ehdr.e_phnum) {
    phdr = (const Elf64_Phdr *)(buf + ehdr.e_phoff);
    for(int i = 0; i < ehdr.e_phnum; i++) {
      uint64_t end = phdr[i].p_offset + phdr[i].p_filesz;
      if(end < phdr[i].p_offset || end > SIZE_MAX) {
        mem_free(buf);
        errno = ENOEXEC;
        return -1;
      }
      if(end > file_end) {
        file_end = end;
      }
    }
  }

  if(ehdr.e_shnum) {
    shdr = (const Elf64_Shdr *)(buf + ehdr.e_shoff);
    for(int i = 0; i < ehdr.e_shnum; i++) {
      if(shdr[i].sh_type == SHT_NOBITS) {
        continue;
      }
      uint64_t end = shdr[i].sh_offset + shdr[i].sh_size;
      if(end < shdr[i].sh_offset || end > SIZE_MAX) {
        mem_free(buf);
        errno = ENOEXEC;
        return -1;
      }
      if(end > file_end) {
        file_end = end;
      }
    }
  }

  if(file_end > size) {
    uint8_t *larger = mem_realloc(buf, file_end);
    if(!larger) {
      mem_free(buf);
      return -1;
    }
    buf = larger;

    rem = file_end - size;
    if(recv(fd, buf + size, rem, MSG_WAITALL) != rem) {
      mem_free(buf);
      return -1;
    }
  }

  if(elfldr_sanity_check(buf, file_end)) {
    mem_free(buf);
    errno = ENOEXEC;
    return -1;
  }

  *elf = buf;
  *elf_size = file_end;

  return 0;
}

pid_t
elfldr_find_pid(const char *name) {
  int mib[4] = { 1, 14, 8, 0 };
  pid_t mypid = getpid();
  pid_t parent = getppid();
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    return -1;
  }

  if(!(buf = mem_alloc(buf_size))) {
    LOG_PERROR("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    LOG_PERROR("sysctl");
    mem_free(buf);
    return -1;
  }

  for(uint8_t *ptr = buf; ptr < buf + buf_size;) {
    int ki_structsize = *(int *)ptr;
    pid_t ki_pid = *(pid_t *)&ptr[72];
    char *ki_tdname = (char *)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname) && ki_pid != mypid && ki_pid != parent) {
      pid = ki_pid;
    }
  }

  mem_free(buf);

  return pid;
}
