#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <getopt.h>

int send_hash_request(const char* filepath) {
    char resp_fifo[MAX_PATH_LEN];

    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }
    request_msg_t req = { .type = REQ_HASH_FILE, .client_pid = getpid() };
    strncpy(req.path, filepath, sizeof(req.path) - 1);
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, "Error: Cannot connect to server! Is the server running?\n");
        unlink(resp_fifo);
        return -1;
    }
   
    int resp_fd = open_fifo_read(resp_fifo);
    if (resp_fd == -1) { perror("open response FIFO"); unlink(resp_fifo); return -1; }
    
    struct pollfd fds[1];
    fds[0].fd = resp_fd;
    fds[0].events = POLLIN;
    int poll_result = poll(fds, 1, 10000); 
    if (poll_result <= 0) {
        if (poll_result == 0) {
            printf("Timeout waiting for server response\n");
            fprintf(stderr, "Timeout waiting for server response\n");
        } else {
            perror("poll");
        }
        close(resp_fd);
        unlink(resp_fifo);
        return -1;
    }
    
    response_msg_t resp;
    if (read_exact(resp_fd, &resp, sizeof(resp)) == -1) {
        perror("read response");
        close(resp_fd);
        unlink(resp_fifo);
        return -1;
    }
    close(resp_fd);
    unlink(resp_fifo);
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = get_time_diff(start_time, end_time);
    
    switch (resp.type) {
        case RESP_HASH:
            printf("File: %s\n", filepath);
            printf("SHA-256: %s\n", resp.hash);
            printf("Time: %.3f ms\n", elapsed * 1000);
            return 0;
            
        case RESP_ERROR:
            fprintf(stderr, "Error: %s (code: %d)\n", resp.error_msg, resp.error_code);
            return -1;
            
        default:
            fprintf(stderr, "Unknown response type: %d\n", resp.type);
            return -1;
    }
}

int send_terminate_request(void) {
    char resp_fifo[MAX_PATH_LEN];
    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());
   
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }

    request_msg_t req = { .type = REQ_TERMINATE, .client_pid = getpid() };
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);
    if (send_request(REQUEST_FIFO_PATH, req) == -1) { fprintf(stderr, "Error: Cannot connect to server\n"); unlink(resp_fifo); return -1; }

    unlink(resp_fifo);
    printf("Termination request sent to server\n");
    return 0;
}

int send_stats_request(void) {
    char resp_fifo[MAX_PATH_LEN];

    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }
    
    request_msg_t req = { .type = REQ_STATS, .client_pid = getpid() };
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);
    if (send_request(REQUEST_FIFO_PATH, req) == -1) { fprintf(stderr, "Error: Cannot connect to server. Is the server running?\n"); unlink(resp_fifo); return -1; }
    
    response_msg_t resp;
    if (read_response(resp_fifo, &resp) == -1) { perror("read response"); unlink(resp_fifo); return -1; }
    unlink(resp_fifo);
    
    if (resp.type == RESP_STATS) {
        printf("=== Server Statistics ===\n"); 
        

        printf("Total requests: %lu\n", resp.stats.total_requests);
        printf("Cache hits: %lu\n", resp.stats.cache_hits);
        printf("Cache misses: %lu\n", resp.stats.cache_misses);
        printf("Files processed: %lu\n", resp.stats.files_processed);

        printf("Average processing time: %.3f ms\n", resp.stats.avg_processing_time * 1000.0);
        
        printf("========================\n"); 
        return 0; 
    } else if (resp.type == RESP_ERROR) {
        fprintf(stderr, "Error getting stats: %s\n", resp.error_msg);
        return -1;
    } else {
        fprintf(stderr, "Unknown response type: %d\n", resp.type);
        return -1;
    }
}

int main(int argc, char* argv[]) {
    int opt;
    int option_index = 0;

    static struct option long_options[] = {
        {"help",      no_argument,       0, 'h'},
        {"path",      required_argument, 0, 'p'},
        {"stats",     no_argument,       0, 's'},
        {"terminate", no_argument,       0, 't'},
        {0,           0,                 0,  0 }
    };

    if (argc < 2) { print_usage(argv[0]); return 1; }

    while ((opt = getopt_long(argc, argv, "hp:st", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': { 
                char abs_path[4096];
                char* filepath = optarg; 

                if (realpath(filepath, abs_path) == NULL) { perror("Errore realpath"); return 1; }

                if (strlen(abs_path) >= MAX_PATH_LEN) { fprintf(stderr, "Errore: Il percorso è troppo lungo\n"); return 1; }

                if (send_hash_request(abs_path) == -1) { fprintf(stderr, "Errore: Invio Richiesta Hash fallito per %s\n", abs_path); return 1; }
                break;
            }
            case 'h': print_usage(argv[0]); return 0;
            case 's': return send_stats_request();
            case 't': return send_terminate_request();
            case '?': print_usage(argv[0]); return 1;
            default:
                abort();
        }
    }

    if (optind < argc) {fprintf(stderr, "Errore: Trovati argomenti non validi:\n");while (optind < argc) { fprintf(stderr, " -> %s\n", argv[optind++]); }return 1;}

    return 0;
}