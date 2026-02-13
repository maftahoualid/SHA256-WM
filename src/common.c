#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

int create_fifo(const char* path, mode_t mode) {
    if (mkfifo(path, mode) == 0) return 0;
    if (errno != EEXIST) { perror(BOLD RED"[ERRORE] mkfifo"); return -1; }
    struct stat st;

    if (stat(path, &st) == 0 && S_ISFIFO(st.st_mode)) { return 0; }
    fprintf(stderr, BOLD RED"[ERRORE] '%s' esiste e non è una FIFO."RES"\n", path);
    return -1;
}

int open_for_reading(const char* path) {
    int fd;
    do {
        fd = open(path, O_RDONLY);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1) { perror(BOLD RED"[ERRORE] open fifo read"RES"\n"); }
    return fd;
}

int open_for_writing(const char* path) {
    int fd;
    do {
        fd = open(path, O_WRONLY);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1) { perror(BOLD RED"[ERRORE] open fifo write"RES"\n"); }
    return fd;
}

int send_response(const char* fifo, response_t resp) {
    int fd = open_for_writing(fifo);
    if (fd == -1) return -1;

    if (write_message(fd, &resp, sizeof(resp)) == -1) { printf(BOLD RED"[ERRORE] Failed to send response to %s"RES"\n", fifo); perror("send_response"); close(fd); return -1;} 
    close(fd);
    return 0;
}

int send_request(const char* server_fifo, request_t req) {
    int fd = open_for_writing(server_fifo);
    if (fd == -1) return -1;

    if (write_message(fd, &req, sizeof(req)) == -1) { printf(BOLD RED"[ERRORE] Failed to send request to %s"RES"\n", server_fifo); perror("send_request"); }
    close(fd);
    return fd;
}

int read_response(const char* fifo, response_t* resp) {
    int fd = open_for_reading(fifo);
    if (fd == -1) return -1;
    
    if (read_message(fd, resp, sizeof(*resp)) == -1) {
        printf(BOLD RED"[ERRORE] Failed to read response to %s"RES"\n", fifo); perror("read_response"); 
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int read_message(int fd, void* buffer, size_t n) {
    char* p = (char*)buffer;
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

int write_message(int fd, const void* buffer, size_t n) {
    const char* p = (const char*)buffer;
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

double elapsed_time(struct timespec start, struct timespec end) {
    double result = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 ; 
    return result;
}

