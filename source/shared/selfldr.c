/* Copyright (C) 2025 John Törnblom
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
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "log.h"
#include "mem.h"
#include "selfldr.h"

typedef struct self_head {
  uint32_t magic;
  uint8_t version;
  uint8_t mode;
  uint8_t endian;
  uint8_t attrs;
  uint32_t key_type;
  uint16_t header_size;
  uint16_t meta_size;
  uint64_t file_size;
  uint16_t num_entries;
  uint16_t flags;
} self_head_t;

typedef struct self_spawn_args {
  int stdio;
  uint8_t *self;
  size_t self_size;
  char *const *argv;
} self_spawn_args_t;

static int
rdup(pid_t pid, int fd) {
  int err;

  if((err = syscall(0x25b, pid, fd)) < 0) {
    errno = -err;
    return -1;
  }

  return err;
}

static int __attribute__((force_align_arg_pointer))
selfldr_rfork_entry(void *ctx) {
  self_spawn_args_t *args = (self_spawn_args_t *)ctx;
  char *const envp[] = { 0 };
  pid_t ppid = getppid();
  char path[PATH_MAX];
  size_t off = 0;
  ssize_t n;
  int fd;

  if(syscall(0x23b, 0)) {
    LOG_PERROR("sys_budget_set");
    return 0;
  }

  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }
  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }
  if(rdup(ppid, args->stdio) < 0) {
    LOG_PERROR("rdup");
    return 0;
  }

  sprintf(path, "/user/temp/payload_%d.self", getpid());
  if((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755)) < 0) {
    LOG_PERROR("open");
    return 0;
  }
  while(off < args->self_size) {
    n = write(fd, args->self + off, args->self_size - off);
    if(n < 0 && errno == EINTR) {
      continue;
    }
    if(n <= 0) {
      if(!n) {
        errno = EIO;
      }
      LOG_PERROR("write");
      close(fd);
      unlink(path);
      return 0;
    }
    off += n;
  }
  if(close(fd)) {
    LOG_PERROR("close");
    unlink(path);
    return 0;
  }

  execve(path, args->argv, envp);
  LOG_PERROR("execve");

  return 0;
}

pid_t
selfldr_spawn(int stdio, char *const argv[], uint8_t *self, size_t self_size) {
  self_spawn_args_t args = { stdio, self, self_size, argv };
  struct kevent evt;
  void *stack;
  pid_t pid;
  int kq;

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
                         selfldr_rfork_entry, &args))
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

  mem_free(stack);
  close(kq);

  return pid;
}

int
selfldr_read(int fd, uint8_t **self, size_t *self_size) {
  self_head_t head;
  uint8_t *buf;

  if(recv(fd, &head, sizeof(head), MSG_PEEK | MSG_WAITALL) != sizeof(head)) {
    return -1;
  }

  if(head.file_size < sizeof(head) || head.file_size > SIZE_MAX) {
    errno = ENOEXEC;
    return -1;
  }
#ifdef __PROSPERO__
  if(head.magic != 0xEEF51454) {
#else
  if(head.magic != 0x1D3D154F) {
#endif
    errno = ENOEXEC;
    return -1;
  }

  if(!(buf = mem_alloc((size_t)head.file_size))) {
    return -1;
  }

  if(recv(fd, buf, head.file_size, MSG_WAITALL) != head.file_size) {
    mem_free(buf);
    return -1;
  }

  *self = buf;
  *self_size = head.file_size;

  return 0;
}
