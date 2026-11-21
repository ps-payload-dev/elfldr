/* Copyright (C) 2026 ItsJokerZz

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

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include "mem.h"
#include "log.h"

typedef union mem_header {
  long double alignment;
  struct {
    size_t mapping_size;
    size_t requested_size;
  } info;
} mem_header_t;

void *
mem_alloc(size_t size) {
  long page_size = sysconf(_SC_PAGESIZE);
  size_t payload_size = size ? size : 1;
  size_t needed;
  size_t mapping_size;
  mem_header_t *header;

  if(page_size <= 0 || payload_size > SIZE_MAX - sizeof(*header)) {
    errno = ENOMEM;
    return 0;
  }

  needed = sizeof(*header) + payload_size;
  if(needed > SIZE_MAX - ((size_t)page_size - 1)) {
    errno = ENOMEM;
    return 0;
  }
  mapping_size = ((needed + (size_t)page_size - 1) / (size_t)page_size)
                 * (size_t)page_size;

  header = mmap(0, mapping_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(header == MAP_FAILED) {
    return 0;
  }

  header->info.mapping_size = mapping_size;
  header->info.requested_size = size;
  return header + 1;
}

void *
mem_realloc(void *ptr, size_t size) {
  mem_header_t *header;
  void *larger;
  size_t copy_size;

  if(!ptr) {
    return mem_alloc(size);
  }
  if(!size) {
    mem_free(ptr);
    return 0;
  }

  header = (mem_header_t *)ptr - 1;
  larger = mem_alloc(size);
  if(!larger) {
    return 0;
  }

  copy_size = header->info.requested_size < size ? header->info.requested_size
                                                 : size;
  memcpy(larger, ptr, copy_size);
  mem_free(ptr);

  return larger;
}

char *
mem_strdup(const char *str) {
  size_t length = strlen(str);
  if(length == SIZE_MAX) {
    errno = ENOMEM;
    return 0;
  }
  size_t size = length + 1;
  char *copy = mem_alloc(size);

  if(copy) {
    memcpy(copy, str, size);
  }
  return copy;
}

void
mem_free(void *ptr) {
  mem_header_t *header;

  if(!ptr) {
    return;
  }

  header = (mem_header_t *)ptr - 1;
  if(munmap(header, header->info.mapping_size)) {
    LOG_PERROR("munmap");
  }
}
