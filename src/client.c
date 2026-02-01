#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <errno.h>

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
    
    fd_set readfds;
    struct timeval timeout;
    FD_ZERO(&readfds);
    FD_SET(resp_fd, &readfds);
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    
    int select_result = select(resp_fd + 1, &readfds, NULL, NULL, &timeout);
    if (select_result <= 0) {
        if (select_result == 0) {
            fprintf(stderr, "Timeout waiting for server response\n");
        } else {
            perror("select");
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
    
    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, "Error: Cannot connect to server\n");
        unlink(resp_fifo);
        return -1;
    }

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
    
    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, "Error: Cannot connect to server. Is the server running?\n");
        unlink(resp_fifo);
        return -1;
    }
    
    response_msg_t resp;
    if (read_response(resp_fifo, &resp) == -1) {
        perror("read response"); 
        unlink(resp_fifo);
        return -1;
    }
    
    unlink(resp_fifo);
    
    if (resp.type == RESP_STATS) {
        printf("=== Server Statistics ===\n");
        
        char* stats_str = resp.error_msg;
        char* token;
        char* saveptr;
        
        token = strtok_r(stats_str, ",", &saveptr);
        while (token) {
            if (strncmp(token, "Requests:", 9) == 0) printf("Total requests: %s\n", token + 9);
            else if (strncmp(token, "Hits:", 5) == 0) printf("Cache hits: %s\n", token + 5);
            else if (strncmp(token, "Misses:", 7) == 0) printf("Cache misses: %s\n", token + 7);
            else if (strncmp(token, "Processed:", 10) == 0) printf("Files processed: %s\n", token + 10);
            else if (strncmp(token, "AvgTime:", 8) == 0) printf("Average processing time: %s ms\n", token + 8);
            token = strtok_r(NULL, ",", &saveptr);
        }
        
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
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stats") == 0) {
            return send_stats_request();
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--terminate") == 0) {
            return send_terminate_request();
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            char* filepath = argv[i];
            char abs_path[4096];
            if (realpath(filepath, abs_path) == NULL) { perror("realpath"); return 1; }
            filepath = abs_path;
            if (strlen(abs_path) >= MAX_PATH_LEN) { fprintf(stderr, "Errore: Il percorso è troppo lungo"); return 1; }
            if (send_hash_request(filepath) == -1) { fprintf(stderr, "Errore: Invio Richiesta Hash fallito"); return 1; }
        }
    }
    return 0;
}
