#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void usage(char *program) {
  fprintf(stderr, "usage: %s {open|creat|openat|openat2|unlink|unlinkat} PATH [FLAGS]\n", program);
  fprintf(stderr, "       %s {rename|renameat|renameat2} OLD_PATH NEW_PATH\n", program);
  fprintf(stderr, "flags: r, w, rw, c=create, t=truncate, a=append, x=exclusive, d=directory\n");
}

static int parse_flags(char *s, int *out) {
  int flags = 0;
  int read = 0;
  int write = 0;

  if (!s || s[0] == '\0') {
    *out = O_RDONLY;
    return 0;
  }

  for (; *s; s++) {
    switch (*s) {
    case 'r':
      read = 1;
      break;
    case 'w':
      write = 1;
      break;
    case 'c':
      flags |= O_CREAT;
      break;
    case 't':
      flags |= O_TRUNC;
      break;
    case 'a':
      flags |= O_APPEND;
      break;
    case 'x':
      flags |= O_EXCL;
      break;
    case 'd':
      flags |= O_DIRECTORY;
      break;
    default:
      errno = EINVAL;
      return -1;
    }
  }

  if (read && write) {
    flags |= O_RDWR;
  } else if (write) {
    flags |= O_WRONLY;
  } else {
    flags |= O_RDONLY;
  }

  *out = flags;
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) {
    usage(argv[0]);
    return 2;
  }

  char *name = argv[1];
  char *path = argv[2];
  char *flag_string = argc == 4 ? argv[3] : NULL;
  int flags = 0;
  int fd = -1;

  if ((strcmp(name, "rename") == 0 || strcmp(name, "renameat") == 0 ||
       strcmp(name, "renameat2") == 0) && argc != 4) {
    usage(argv[0]);
    return 2;
  }

  if (strcmp(name, "creat") != 0 && strcmp(name, "unlink") != 0 &&
      strcmp(name, "unlinkat") != 0 && strcmp(name, "rename") != 0 &&
      strcmp(name, "renameat") != 0 && strcmp(name, "renameat2") != 0 &&
      parse_flags(flag_string, &flags) < 0) {
    perror("flags");
    return 2;
  }

  if (strcmp(name, "open") == 0) {
    fd = syscall(SYS_open, path, flags, 0666);
  } else if (strcmp(name, "creat") == 0) {
    fd = syscall(SYS_creat, path, 0666);
  } else if (strcmp(name, "openat") == 0) {
    fd = syscall(SYS_openat, AT_FDCWD, path, flags, 0666);
  } else if (strcmp(name, "openat2") == 0) {
    struct open_how how = {
        .flags = flags,
        .mode = (flags & O_CREAT) ? 0666 : 0,
    };

    fd = syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
  } else if (strcmp(name, "unlink") == 0) {
    return syscall(SYS_unlink, path) == 0 ? 0 : (perror(name), 1);
  } else if (strcmp(name, "unlinkat") == 0) {
    return syscall(SYS_unlinkat, AT_FDCWD, path, 0) == 0 ? 0 : (perror(name), 1);
  } else if (strcmp(name, "rename") == 0) {
    return syscall(SYS_rename, path, argv[3]) == 0 ? 0 : (perror(name), 1);
  } else if (strcmp(name, "renameat") == 0) {
    return syscall(SYS_renameat, AT_FDCWD, path, AT_FDCWD, argv[3]) == 0 ? 0 : (perror(name), 1);
  } else if (strcmp(name, "renameat2") == 0) {
    return syscall(SYS_renameat2, AT_FDCWD, path, AT_FDCWD, argv[3], 0) == 0 ? 0 : (perror(name), 1);
  } else {
    usage(argv[0]);
    return 2;
  }

  if (fd < 0) {
    perror(name);
    return 1;
  }

  close(fd);
  return 0;
}
