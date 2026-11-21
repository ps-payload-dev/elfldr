/* Copyright (C) 2024 John Törnblom
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

#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct elfldr_ctx {
  const uint8_t *elf;
  pid_t pid;

  intptr_t base_addr;
  size_t base_size;
  uintptr_t min_vaddr;
  void *base_mirror;
} elfldr_ctx_t;

int r_relative(elfldr_ctx_t *ctx, const Elf64_Rela *rela);
int data_load(elfldr_ctx_t *ctx, const Elf64_Phdr *phdr);

pid_t elfldr_spawn(const char *cwd, int stdio, char *const argv[],
                   char *const envp[], const uint8_t *elf, size_t elf_size);
pid_t elfldr_spawn_legacy(int stdio, char *const argv[], const uint8_t *elf,
                          size_t elf_size);

int elfldr_exec(pid_t pid, int stdio, const uint8_t *elf);

int elfldr_read(int fd, uint8_t **elf, size_t *elf_size);

int elfldr_sanity_check(const uint8_t *elf, size_t elf_size);

intptr_t elfldr_load(pid_t pid, const uint8_t *elf);

intptr_t elfldr_payload_args(pid_t pid);

pid_t elfldr_find_pid(const char *name);

int elfldr_raise_privileges(pid_t pid);
int elfldr_set_cwd(pid_t pid, const char *cwd);
int elfldr_set_environ(pid_t pid, char *const envp[]);
int elfldr_set_procname(pid_t pid, const char *name);
int elfldr_set_stdio(pid_t pid, int stdio);
int elfldr_set_heap_size(pid_t pid, ssize_t size);

#ifdef __cplusplus
}
#endif

#ifndef ELFLDR_IMPLEMENTATION
#define ELFLDR_SPAWN_SELECT(_1, _2, _3, _4, _5, _6, NAME, ...) NAME
#define elfldr_spawn(...)                                                     \
  ELFLDR_SPAWN_SELECT(__VA_ARGS__, elfldr_spawn, elfldr_spawn_bad_arity,      \
                      elfldr_spawn_legacy)                                    \
  (__VA_ARGS__)
#endif
int elfldr_set_cwd(pid_t pid, const char *cwd);
int elfldr_set_environ(pid_t pid, char *const envp[]);
int elfldr_set_procname(pid_t pid, const char *name);
int elfldr_set_stdio(pid_t pid, int stdio);
int elfldr_set_heap_size(pid_t pid, ssize_t size);
