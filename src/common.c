#include "common.h"
#include <stdio.h>      // printf, perror
#include <stdlib.h>     // exit, NULL
#include <string.h>     // strerror
#include <unistd.h>     // read, write, close, unlink, read
#include <fcntl.h>      // open, O_RDONLY, O_WRONLY
#include <errno.h>      // errno, EEXIST, EINTR
#include <sys/stat.h>   // stat, mkfifo, S_ISFIFO

int ensure_fifo(const char* path, mode_t mode) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISFIFO(st.st_mode)) {
            return 0;
        } else {
            // Se esiste ma non è una FIFO, prova a rimuoverlo
            unlink(path);
        }
    }

    if (mkfifo(path, mode) == -1) {
        if (errno == EEXIST) {
            return 0;
        }
        perror("mkfifo");
        return -1;
    }
    return 0;
}

int open_fifo_read(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open fifo read");
    }
    return fd;
}

int open_fifo_write(const char* path) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open fifo write");
    }
    return fd;
}

int send_response(const char* fifo, response_msg_t resp) {
    int fd = open_fifo_write(fifo);
    if (fd != -1) {
        if (write_exact(fd, &resp, sizeof(resp)) == -1) {
            printf("Warning: Failed to send response to %s\n", fifo);
        }
        close(fd);
    }
    return fd;
}

int read_exact(int fd, void* buf, size_t n) {
    char* p = (char*)buf;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t bytes_read = read(fd, p, remaining);
        if (bytes_read <= 0) {
            if (bytes_read == -1 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += bytes_read;
        remaining -= bytes_read;
    }
    return 0;
}

int write_exact(int fd, const void* buf, size_t n) {
    const char* p = (const char*)buf;
    size_t remaining = n;

    while (remaining > 0) {
        ssize_t bytes_written = write(fd, p, remaining);
        if (bytes_written <= 0) {
            if (bytes_written == -1 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += bytes_written;
        remaining -= bytes_written;
    }
    return 0;
}

double get_time_diff(struct timespec start, struct timespec end) {
    double result = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 ;
    return result;
}

void print_usage(const char* progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -w, --workers N         Number of worker threads (default: 4)\n");
    printf("  -o, --order asc|desc    File processing order (default: asc)\n");
    printf("  -s, --stats             Show server statistics\n");
    printf("  -t, --terminate         Terminate server\n");
    printf("  FILE                    Request hash for FILE\n");
}
