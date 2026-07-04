#define _GNU_SOURCE
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

struct config configs[1024] = {{
                                   .program = "*",
                                   .pattern = "/etc/localtime",
                                   .read = PERM_ALLOW,
                                   .write = PERM_DENY,
                               },
                               {
                                   .program = "*",
                                   .pattern = "/nix/store/*",
                                   .read = PERM_ALLOW,
                                   .write = PERM_DENY,
                               },
                               {
                                   .program = "*",
                                   .pattern = "/run/current-system/*",
                                   .read = PERM_ALLOW,
                                   .write = PERM_DENY,
                               }};
// /run/current-system/sw/lib/locale/locale-archive

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

  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sendmsg, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_exit_group, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
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

      if (req.data.nr == SYS_openat) {
        int dirfd = (int)(int32_t)req.data.args[0];
        char path[4096];
        if (read_child_string(req.pid, (void *)req.data.args[1], path,
                              sizeof(path)) < 0) {
          perror("read_child_string");
          return 1;
        }

        if (path[0] != '/') {
          char cwd[4096];

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

          memmove(path + strlen(cwd) + 1, path, strlen(path) + 1);
          strncpy(path, cwd, strlen(cwd));
          path[strlen(cwd)] = '/';

          // FIXME: it works in my machine 🫣
          realpath(path, path);
        }

        struct config current_conf = {
            .read = PERM_ASK,
            .write = PERM_ASK,
        };

        for (int i = 1023; i >= 0; i--) {
          if (!configs[i].program || !configs[i].pattern) {
            continue;
          }

          if ((strcmp(configs[i].program, "*") == 0 ||
               strcmp(configs[i].program, argv[1]) == 0) &&
              fnmatch(configs[i].pattern, path, 0) == 0) {
            /* printf("found pattern: %s (%d)\n", configs[i].pattern, i); */
            current_conf = configs[i];
            break;
          }
        }

        bool want_read = false;
        bool want_write = false;

        int flags = (int)req.data.args[2];
        char sflag[30];
        switch (flags & O_ACCMODE) {
        case O_RDONLY:
          want_read = true;
          snprintf(sflag, sizeof(sflag), "read from");
          break;
        case O_WRONLY:
          want_write = true;
          snprintf(sflag, sizeof(sflag), "write to");
          break;
        case O_RDWR:
          want_read = true;
          want_write = true;
          snprintf(sflag, sizeof(sflag), "read AND write to");
          break;
        default:
          snprintf(sflag, sizeof(sflag), "%d", flags);
          break;
        }

        if ((want_read && current_conf.read == PERM_DENY) ||
            (want_write && current_conf.write == PERM_DENY)) {
          resp.flags = 0;
          resp.error = -EACCES;
        } else if ((want_read && current_conf.read != PERM_ALLOW) ||
                   (want_write && current_conf.write != PERM_ALLOW)) {
          fprintf(stderr, "May I %s '%s'? [Y/n]: ", sflag, path);
          fflush(stdout);

          if (getchar() == 'n') {
            resp.flags = 0;
            resp.error = -EACCES;
          }
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
