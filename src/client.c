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
    char response_fifo_path[MAX_PATH_LEN];

    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }
    request_msg_t req = { .type = REQ_HASH_FILE, .pid = getpid() };
    strncpy(req.path, filepath, sizeof(req.path) - 1);
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    struct timespec start_time, end_time;
    clock_gettime(1, &start_time);

    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Cannot connect to server! Is the server isrunning?"RES"\n");
        unlink(response_fifo_path);
        return -1;
    }
   
    int resp_fd = open_fifo_read(response_fifo_path);
    if (resp_fd == -1) { perror(BOLD RED"[CLIENT][ERRORE] open response FIFO"RES"\n"); unlink(response_fifo_path); return -1; }
    
    struct pollfd fds[1];
    fds[0].fd = resp_fd;
    fds[0].events = POLLIN;
    int poll_result = poll(fds, 1, 10000); 
    if (poll_result <= 0) {
        if (poll_result == 0) {
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Timeout waiting for server response"RES"\n");
        } else {
            perror(BOLD RED"poll"RES"\n");
        }
        close(resp_fd);
        unlink(response_fifo_path);
        return -1;
    }
    
    response_msg_t resp;
    if (read_exact(resp_fd, &resp, sizeof(resp)) == -1) {
        perror(BOLD RED"[CLIENT][ERRORE] read response"RES"\n");
        close(resp_fd);
        unlink(response_fifo_path);
        return -1;
    }
    close(resp_fd);
    unlink(response_fifo_path);
    
    clock_gettime(1, &end_time);
    double elapsed = get_time_diff(start_time, end_time);
    
    switch (resp.type) {
        case RESP_HASH:
            printf(BOLD BLUE"[CLIENT][INFO] File: %s"RES"\n", filepath);
            printf(BOLD BLUE"[CLIENT][INFO] SHA-256: %s"RES"\n", resp.hash);
            printf(BOLD BLUE"[CLIENT][INFO] Time: %.3f ms"RES"\n", elapsed * 1000);
            return 0;
            
        case RESP_ERROR:
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] %s (code: %d)"RES"\n", resp.message, resp.error_code);
            return -1;
            
        default:
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Unknown response type: %d"RES"\n", resp.type);
            return -1;
    }
}

int send_terminate_request(void) {
    char response_fifo_path[MAX_PATH_LEN];
    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PREFIX, getpid());
   
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }

    request_msg_t req = { .type = REQ_TERMINATE, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    if (send_request(REQUEST_FIFO_PATH, req) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Cannot connect to server"RES"\n"); unlink(response_fifo_path); return -1; }

    unlink(response_fifo_path);
    printf(BOLD BLUE"[CLIENT][INFO] Termination request sent to server"RES"\n");
    return 0;
}

int send_stats_request(void) {
    char response_fifo_path[MAX_PATH_LEN];

    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }
    
    request_msg_t req = { .type = REQ_STATS, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    if (send_request(REQUEST_FIFO_PATH, req) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Cannot connect to server. Is the server isrunning?"RES"\n"); unlink(response_fifo_path); return -1; }
    
    response_msg_t resp;
    if (read_response(response_fifo_path, &resp) == -1) { perror(BOLD RED"[CLIENT][ERRORE] read response"RES"\n"); unlink(response_fifo_path); return -1; }
    unlink(response_fifo_path);
    
    if (resp.type == RESP_STATS) {
        printf(BOLD BLUE"[CLIENT][INFO] === Server Statistics ==="RES"\n"); 
        printf(BOLD BLUE"[CLIENT][INFO] Total requests: %lu"RES"\n", resp.stats.total_requests);
        printf(BOLD BLUE"[CLIENT][INFO] Cache hits: %lu"RES"\n", resp.stats.cache_hits);
        printf(BOLD BLUE"[CLIENT][INFO] Cache misses: %lu"RES"\n", resp.stats.cache_misses);
        printf(BOLD BLUE"[CLIENT][INFO] Files processed: %lu"RES"\n", resp.stats.files_processed);
        printf(BOLD BLUE"[CLIENT][INFO] Average processing time: %.3f ms"RES"\n", resp.stats.avg_processing_time * 1000.0);
        return 0; 
    } else if (resp.type == RESP_ERROR) {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Error getting stats: %s"RES"\n", resp.message);
        return -1;
    } else {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Unknown response type: %d"RES"\n", resp.type);
        return -1;
    }
}

int main(int argc, char* argv[]) {
    int opt;
    int option_index = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
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

                if (realpath(filepath, abs_path) == NULL) { perror(BOLD RED"[CLIENT][ERRORE] realpath"RES"\n"); return 1; }

                if (strlen(abs_path) >= MAX_PATH_LEN) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Il percorso è troppo lungo"RES"\n"); return 1; }

                if (send_hash_request(abs_path) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Invio Richiesta Hash fallito per %s"RES"\n", abs_path); return 1; }
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

    if (optind < argc) {fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Trovati argomenti non validi:"RES"\n");while (optind < argc) { fprintf(stderr, BOLD RED" -> %s"RES"\n", argv[optind++]); }return 1;}

    return 0;
}