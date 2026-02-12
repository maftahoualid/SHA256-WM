#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

int ensure_fifo(const char* path, mode_t mode) {
    if (mkfifo(path, mode) == 0) return 0;
    if (errno != EEXIST) { perror("mkfifo"); return -1; }
    struct stat st;

    if (stat(path, &st) == 0 && S_ISFIFO(st.st_mode)) { return 0; }
    fprintf(stderr, "Errore: '%s' esiste e non è una FIFO.\n", path);
    return -1;
}

int open_fifo_read(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) { perror("open fifo read"); }
    return fd;
}

int open_fifo_write(const char* path) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) { perror("open fifo write"); }
    return fd;
}

int send_response(const char* fifo, response_msg_t resp) {
    int fd = open_fifo_write(fifo);
    if (fd == -1) return -1;

    if (write_exact(fd, &resp, sizeof(resp)) == -1) { printf("Warning: Failed to send response to %s\n", fifo); } 
    close(fd);
    return fd;
}

int send_request(const char* server_fifo, request_msg_t req) {
    int fd = open_fifo_write(server_fifo);
    if (fd == -1) return -1;

    if (write_exact(fd, &req, sizeof(req)) == -1) { printf("Warning: Failed to send request to %s\n", server_fifo); }
    close(fd);
    return fd;
}

int read_response(const char* fifo, response_msg_t* resp) {
    int fd = open_fifo_read(fifo);
    if (fd == -1) return -1;
    
    if (read_exact(fd, resp, sizeof(*resp)) == -1) {
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
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