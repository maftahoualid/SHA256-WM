#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

int crea_fifo(const char* path, mode_t permessi) {
    if (mkfifo(path, permessi) == 0) return 0;
    if (errno != EEXIST) { perror("mkfifo"); return -1; }
    struct stat stat_file;

    if (stat(path, &stat_file) == 0 && S_ISFIFO(stat_file.st_mode)) { return 0; }
    fprintf(stderr, "Errore: '%s' esiste e non è una FIFO.\n", path);
    return -1;
}

int apri_fifo_lettura(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd == -1) { perror("open fifo read"); }
    return fd;
}

int apri_fifo_scrittura(const char* path) {
    int fd = open(path, O_WRONLY | O_NONBLOCK);
    if (fd == -1) {
        if (errno != ENXIO) {
            perror("open fifo write"); 
        }
    }
    return fd;
}

int invia_risposta(const char* fifo, messaggio_risposta_t risposta) {
    int fd = apri_fifo_scrittura(fifo);
    if (fd == -1) return -1;

    if (scrivi_su(fd, &risposta, sizeof(risposta)) == -1) { printf("Warning: Failed to send response to %s\n", fifo); } 
    close(fd);
    return fd;
}

int invia_richiesta(const char* fifo, messaggio_richiesta_t req) {
    int fd = apri_fifo_scrittura(fifo);
    if (fd == -1) return -1;

    if (scrivi_su(fd, &req, sizeof(req)) == -1) { printf("Warning: Failed to send request to %s\n", fifo); }
    close(fd);
    return fd;
}

int leggi_risposta(const char* fifo, messaggio_risposta_t* risposta) {
    int fd = apri_fifo_lettura(fifo);
    if (fd == -1) return -1;
    
    if (leggi_da_fifo(fd, risposta, sizeof(*risposta)) == -1) {
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

int leggi_da_fifo(int fd, void* buf, size_t n) {
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

int scrivi_su(int fd, const void* buf, size_t n) {
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

double differenza(struct timespec start, struct timespec end) {

    double result = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 ; 
    return result;
}

void stampa_menu(const char* progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -w, --workers N         Number of worker threads (default: 4)\n");
    printf("  -o, --order asc|desc    File processing order (default: asc)\n");
    printf("  -s, --stats             Show server statistics\n");
    printf("  -t, --terminate         Terminate server\n");
    printf("  FILE                    Request hash for FILE\n");
}