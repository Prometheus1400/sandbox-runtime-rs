#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static int send_fd(int socket_fd, int fd_to_send) {
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    char payload = 'F';
    struct iovec io = {
        .iov_base = &payload,
        .iov_len = sizeof(payload),
    };
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd_to_send, sizeof(int));

    return sendmsg(socket_fd, &msg, 0);
}

static int connect_notify_socket(const char *socket_path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    size_t path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, socket_path, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return fd;
}

static struct sock_filter *load_filter(const char *path, unsigned short *out_len) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return NULL;
    }

    if (st.st_size <= 0 || (st.st_size % sizeof(struct sock_filter)) != 0) {
        errno = EINVAL;
        return NULL;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    size_t len = (size_t)(st.st_size / sizeof(struct sock_filter));
    struct sock_filter *filter = calloc(len, sizeof(struct sock_filter));
    if (filter == NULL) {
        close(fd);
        return NULL;
    }

    ssize_t remaining = st.st_size;
    char *cursor = (char *)filter;
    while (remaining > 0) {
        ssize_t read_bytes = read(fd, cursor, (size_t)remaining);
        if (read_bytes <= 0) {
            int saved = errno;
            free(filter);
            close(fd);
            errno = saved == 0 ? EIO : saved;
            return NULL;
        }
        remaining -= read_bytes;
        cursor += read_bytes;
    }

    close(fd);
    *out_len = (unsigned short)len;
    return filter;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <notify-socket-path> <bpf-path> <program> [args...]\n", argv[0]);
        return 64;
    }

    int notify_socket_fd = connect_notify_socket(argv[1]);
    if (notify_socket_fd < 0) {
        perror("connect(notify_socket)");
        return 70;
    }
    const char *bpf_path = argv[2];

    unsigned short filter_len = 0;
    struct sock_filter *filter = load_filter(bpf_path, &filter_len);
    if (filter == NULL) {
        perror("failed to load seccomp filter");
        return 65;
    }

    struct sock_fprog prog = {
        .len = filter_len,
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        free(filter);
        return 66;
    }

    int listener_fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
    if (listener_fd < 0) {
        perror("seccomp(SECCOMP_SET_MODE_FILTER)");
        free(filter);
        return 67;
    }

    free(filter);

    if (send_fd(notify_socket_fd, listener_fd) < 0) {
        perror("sendmsg(listener_fd)");
        close(listener_fd);
        return 68;
    }

    close(notify_socket_fd);
    close(listener_fd);

    execvp(argv[3], &argv[3]);
    perror("execvp");
    return 69;
}

#else
int main(void) {
    return 1;
}
#endif
