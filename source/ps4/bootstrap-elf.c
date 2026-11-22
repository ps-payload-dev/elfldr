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

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/thr.h>
#include <unistd.h>

#include <ps4/kernel.h>
#include <ptrace.h>

#include "asset.h"
#include "elfldr.h"
#include "log.h"
#include "notify.h"

INCASSET(socksrv_elf, "build/ps4/objects/socksrv.elf");

static char *const argv[] = { "elfldr.elf", 0 };

static void
get_thread_name(char name[32]) {
  int mib[4] = { 1, 14, 1, getpid() };
  uint8_t info[2048];
  size_t size = sizeof(info);

  name[0] = 0;
  if(!sysctl(mib, 4, info, &size, 0, 0) && size > 447) {
    strncpy(name, (const char *)&info[447], 31);
    name[31] = 0;
  }
}

int
main(void) {
  char thread_name[32];
  unsigned char privcaps[16]
      = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  unsigned char caps[16];
  unsigned long jaildir;
  unsigned long rootdir;
  unsigned long prison;
  uint8_t qaflags[16];
  int err;

  get_thread_name(thread_name);
  thr_set_name(-1, "elfldr bootstrap");
  LOG_PUTS("Bootstrapping elfldr.elf...");

  if(patch_ps4_ptrace()) {
    LOG_PERROR("patch_ps4_ptrace");
  }

  if(kernel_get_qaflags(qaflags)) {
    LOG_PERROR("kernel_get_qaflags");
    return -1;
  }

  qaflags[1] |= 3;
  if(kernel_set_qaflags(qaflags)) {
    LOG_PERROR("kernel_set_qaflags");
    return -1;
  }

  if((err = kernel_get_ucred_caps(-1, caps))) {
    LOG_PUTS("kernel_get_ucred_caps failed");
    return err;
  }
  if(!(prison = kernel_get_ucred_prison(-1))) {
    LOG_PUTS("kernel_get_ucred_prison failed");
    return -1;
  }
  if(!(rootdir = kernel_get_proc_rootdir(-1))) {
    LOG_PUTS("kernel_get_proc_rootdir failed");
    return -1;
  }
  jaildir = kernel_get_proc_jaildir(-1);

  if((err = kernel_set_ucred_caps(-1, privcaps))) {
    LOG_PUTS("kernel_set_ucred_caps failed");

  } else if((err = kernel_set_ucred_prison(-1, KERNEL_ADDRESS_PRISON0))) {
    LOG_PUTS("kernel_set_proc_rootdir failed");

  } else if((err = kernel_set_proc_rootdir(-1, KERNEL_ADDRESS_ROOTVNODE))) {
    LOG_PUTS("kernel_set_proc_rootdir failed");

  } else if((err = kernel_set_proc_jaildir(-1, KERNEL_ADDRESS_ROOTVNODE))) {
    LOG_PUTS("kernel_set_proc_jaildir failed");
  }

  if(!err) {
    signal(SIGCHLD, SIG_IGN);
    err = elfldr_spawn(-1, argv, socksrv_elf, socksrv_elf_size);
  }

  if(kernel_set_ucred_caps(-1, caps)) {
    LOG_PUTS("kernel_set_ucred_caps failed");
    err = -1;
  }
  if(kernel_set_ucred_prison(-1, prison)) {
    LOG_PUTS("kernel_set_proc_rootdir failed");
    err = -1;
  }
  if(kernel_set_proc_rootdir(-1, rootdir)) {
    LOG_PUTS("kernel_set_proc_rootdir failed");
    err = -1;
  }
  if(kernel_set_proc_jaildir(-1, jaildir)) {
    LOG_PUTS("kernel_set_proc_jaildir failed");
    err = -1;
  }
  if(thread_name[0]) {
    thr_set_name(-1, thread_name);
  }

  return err;
}
