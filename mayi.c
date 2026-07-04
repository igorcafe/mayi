#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

bool str_has_prefix(char *str, char *prefix) {
  size_t len = strlen(prefix);
  return strncmp(str, prefix, len) == 0;
}

int send_fd(int sock, int fd) {
  char buf = '_';

  struct iovec io = {
      .iov_base = &buf,
      .iov_len = sizeof(buf),
  };

  char cmsgbuf[CMSG_SPACE(sizeof(fd))];

  struct msghdr msg = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = cmsgbuf,
      .msg_controllen = sizeof(cmsgbuf),
  };

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

  memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

  return sendmsg(sock, &msg, 0);
}

int recv_fd(int sock) {
  char buf;

  struct iovec io = {
      .iov_base = &buf,
      .iov_len = sizeof(buf),
  };

  char cmsgbuf[CMSG_SPACE(sizeof(int))];

  struct msghdr msg = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = cmsgbuf,
      .msg_controllen = sizeof(cmsgbuf),
  };

  if (recvmsg(sock, &msg, 0) < 0)
    return -1;

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg)
    return -1;

  int fd;
  memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
  return fd;
}

ssize_t read_child_string(pid_t pid, void *addr, char *buf, size_t size) {
  struct iovec local = {
      .iov_base = buf,
      .iov_len = size - 1,
  };

  struct iovec remote = {
      .iov_base = (void *)addr,
      .iov_len = size - 1,
  };

  ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
  if (n < 0)
    return -1;

  buf[n] = '\0';

  char *nul = memchr(buf, '\0', n);
  if (nul)
    *(nul + 1) = '\0';

  return n;
}

enum config_perm {
  PERM_DENY,
  PERM_ASK,
  PERM_ALLOW,
};

struct config {
  char *program;
  char *pattern;
  enum config_perm read;
  enum config_perm write;
};

struct config configs[1024] = {0};
// /run/current-system/sw/lib/locale/locale-archive

void parse_config(FILE *file) {
  int i = 0;
  char line[1000];
  char *program = NULL;
  while (fgets(line, sizeof(line), file) != NULL) {
    /* printf("%s", line); */
    if (line[0] == '[' && line[strlen(line) - 2] == ']') {
      line[strlen(line) - 2] = '\0';
      program = strdup(&line[1]);
    } else {
      char key[500];
      char val[500];

      if (sscanf(line, " %499[^ =] = %499[^\n]", key, val) == 2) {
        enum config_perm read = PERM_ASK;
        enum config_perm write = PERM_ASK;

        if (strstr(val, "read:deny")) {
          read = PERM_DENY;
        } else if (strstr(val, "read:ask")) {
          read = PERM_ASK;
        } else if (strstr(val, "read")) {
          read = PERM_ALLOW;
        }

        if (strstr(val, "write:deny")) {
          write = PERM_DENY;
        } else if (strstr(val, "write:ask")) {
          write = PERM_ASK;
        } else if (strstr(val, "write")) {
          write = PERM_ALLOW;
        }

        configs[i] = (struct config){
            .program = strdup(program),
            .pattern = strdup(key),
            .read = read,
            .write = write,
        };
        i++;

        if (i >= sizeof(configs) / sizeof(configs[0])) {
          break;
        }
      }
    }
  }
}

int proc_cwd(int pid, int dirfd, char *cwd, size_t max) {
  if (dirfd == AT_FDCWD) {
    char procpath[100];
    snprintf(procpath, sizeof(procpath), "/proc/%d/cwd", pid);
    ssize_t n = readlink(procpath, cwd, sizeof(procpath) - 1);
    if (n < 0) {
      perror("readlink cwd");
      return 1;
    }
    cwd[n] = '\0';
  } else {
    char procpath[100];
    snprintf(procpath, sizeof(procpath), "/proc/%d/fd/%d", pid, dirfd);
    ssize_t n = readlink(procpath, cwd, sizeof(procpath) - 1);
    if (n < 0) {
      perror("readlink fd");
      return 1;
    }
    cwd[n] = '\0';
  }
  return 0;
}

int resolve_path(int dirfd, char *cwd, char *path) {
  static char path2[2048];

  if (path[0] == '/') {
    return 0;
  }

  memmove(path + strlen(cwd) + 1, path, 2048);
  strncpy(path, cwd, strlen(cwd));
  path[strlen(cwd)] = '/';

  realpath(path, path2);
  strncpy(path, path2, 2048);

  return 0;
}

void find_config(struct config *config, char *program, char *path) {
  for (int i = 1023; i >= 0; i--) {
    if (!configs[i].program || !configs[i].pattern) {
      continue;
    }

    if (configs[i].pattern[0] == '$') {
      char *var = getenv(&configs[i].pattern[1]);
      if (!var) {
        continue;
      }
      configs[i].pattern = var;
    }

    if ((strcmp(configs[i].program, "*") == 0 ||
         strcmp(configs[i].program, program) == 0) &&
        fnmatch(configs[i].pattern, path, 0) == 0) {
      /* printf("found pattern: %s (%d)\n", configs[i].pattern, i); */
      *config = configs[i];
      break;
    }
  }
}

enum config_perm get_perm(struct config conf, bool read, bool write) {
  if ((read && conf.read == PERM_DENY) || (write && conf.write == PERM_DENY)) {
    return PERM_DENY;
  }

  if ((read && conf.read == PERM_ASK) || (write && conf.write == PERM_ASK)) {
    return PERM_ASK;
  }

  return PERM_ALLOW;
}

void handle_open(struct config conf, char *path, int flags) {}

#ifndef TEST
int main(int argc, char **argv) {
  if (argc < 2) {
    printf("args: ");
    for (int i = 0; i < argc; i++) {
      printf("%s ", argv[i]);
    }
    printf("\n");
    printf("missing target program\n");
    return 1;
  }

  if (getenv("MAYI_CONFIG")) {
    FILE *file = fopen(getenv("MAYI_CONFIG"), "r");
    if (file) {
      parse_config(file);
    }
  } else if (getenv("HOME")) {
    char path[300];
    snprintf(path, sizeof(path), "%s/.config/mayi.ini", getenv("HOME"));
    FILE *file = fopen(path, "r");
    if (file) {
      parse_config(file);
      /* exit(0); */
    }
  }

  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_creat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlink, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unlinkat, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    perror("couldn't use seccomp in unprivileged mode");
    return 1;
  }

  struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
  };

  int sockets[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) {
    perror("failed to open socket");
    return 1;
  }

  int sock_parent = sockets[0];
  int sock_child = sockets[1];

  pid_t pid = fork();
  if (pid < 0) {
    perror("failed to fork");
    return 1;
  }

  // child process
  if (pid == 0) {
    close(sock_parent);

    int fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                     SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (fd < 0) {
      perror("seccomp");
      return 1;
    }

    if (send_fd(sock_child, fd) < 0) {
      perror("failed to send fd to parent");
      return 1;
    }

    execvp(argv[1], &argv[1]);
  } else {
    close(sock_child);
    int fd = recv_fd(sock_parent);
    if (fd < 0) {
      perror("(parent) failed to recv fd from child");
      return 1;
    }

    while (1) {
      struct seccomp_notif req = {0};
      struct seccomp_notif_resp resp = {0};
      if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
        if (errno == ENOENT) {
          break;
        }
        perror("(parent) SECCOMP_IOCTL_NOTIF_RECV");
        return 1;
      }

      resp.id = req.id;
      resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

      char path[2048];
      enum config_perm perm = PERM_ALLOW;
      bool read = false;
      bool write = false;
      char prompt[4096] = "";

      struct config conf = {
          .program = argv[1],
          .read = PERM_ASK,
          .write = PERM_ASK,
      };

      if (req.data.nr == SYS_unlink || req.data.nr == SYS_unlinkat) {
        write = true;
        int dirfd = AT_FDCWD;
        void *raw_path = NULL;

        if (req.data.nr == SYS_unlink) {
          raw_path = (void *)req.data.args[0];
        } else {
          dirfd = (int)(int32_t)req.data.args[0];
          raw_path = (void *)req.data.args[1];
        }

        if (read_child_string(req.pid, raw_path, path, sizeof(path)) < 0) {
          perror("read_child_string");
          return 1;
        }
        char cwd[4096];
        proc_cwd(pid, dirfd, cwd, sizeof(cwd));
        if (resolve_path(dirfd, cwd, path) != 0) {
          return 1;
        }

        find_config(&conf, argv[1], path);
        perm = get_perm(conf, read, write);

        snprintf(prompt, sizeof(prompt),
                 "May I delete your '%s'? [Y/n]: ", path);
      }

      if (req.data.nr == SYS_open || req.data.nr == SYS_creat ||
          req.data.nr == SYS_openat || req.data.nr == SYS_openat2) {
        int dirfd = AT_FDCWD;
        void *raw_path = NULL;
        int flags = 0;

        if (req.data.nr == SYS_open) {
          raw_path = (void *)req.data.args[0];
          flags = (int)req.data.args[1];
        } else if (req.data.nr == SYS_creat) {
          raw_path = (void *)req.data.args[0];
          flags = O_WRONLY | O_CREAT | O_TRUNC;
        } else {
          dirfd = (int)(int32_t)req.data.args[0];
          raw_path = (void *)req.data.args[1];

          // FIXME: openat2 uses open_how struct instead of int flags
          flags = (int)req.data.args[2];
        }

        if (read_child_string(req.pid, raw_path, path, sizeof(path)) < 0) {
          perror("read_child_string");
          return 1;
        }
        char cwd[4096];
        proc_cwd(pid, dirfd, cwd, sizeof(cwd));
        if (resolve_path(dirfd, cwd, path) != 0) {
          return 1;
        }

        find_config(&conf, argv[1], path);

        switch (flags & O_ACCMODE) {
        case O_RDONLY:
          read = true;
          snprintf(prompt, sizeof(prompt),
                   "May I read your '%s'? [Y/n]: ", path);
          break;
        case O_WRONLY:
          write = true;
          snprintf(prompt, sizeof(prompt),
                   "May I write to your '%s'? [Y/n]: ", path);
          break;
        case O_RDWR:
          read = true;
          write = true;
          snprintf(prompt, sizeof(prompt),
                   "May I read AND write to your '%s'? [Y/n]: ", path);
          break;
        default:
          fprintf(stderr, "unexpected flags: %016b\n", flags & O_ACCMODE);
          return 1;
        }

        if (flags & (O_CREAT | O_TRUNC | O_APPEND)) {
          snprintf(prompt, sizeof(prompt),
                   "May I write to your '%s'? [Y/n]: ", path);
          write = true;
        }

        perm = get_perm(conf, read, write);
      }

      if (perm == PERM_DENY) {
        resp.flags = 0;
        resp.error = -EACCES;
      } else if (perm == PERM_ASK) {
        fprintf(stdout, "%s", prompt);
        fflush(stdout);
        char answer = getchar();
        if (answer == 'n') {
          resp.flags = 0;
          resp.error = -EACCES;
        }
      }

      if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        perror("(parent) SECCOMP_IOCTL_NOTIF_SEND");
        return 1;
      }
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(status)) {
      int code = WEXITSTATUS(status);
      return code;
    } else if (WIFSIGNALED(status)) {
      int signal = WTERMSIG(status);
      printf("killed by signal %d\n", signal);
    }
  }
}

#else
int main(int argc, char **argv) {
  char tests[][3][100] = {
      {"/tmp", ".", "/tmp"},
      {"/tmp", "./", "/tmp"},
      {"/tmp", "..", "/"},
      {"/tmp", "./abc/", "/tmp/abc"},
  };

  for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    char *cwd = tests[i][0];
    char *path = tests[i][1];
    char *want = tests[i][2];
    assert(resolve_path(AT_FDCWD, cwd, path) == 0);
    printf("want: %s\ngot: %s\n", want, path);
    assert(strcmp(path, want) == 0);
  }
}
#endif
