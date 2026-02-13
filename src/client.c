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
    char response_fifo_path[PATH_MAX_LEN];

    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
    if (create_fifo(response_fifo_path, 0777) == -1) { return -1; }
    request_t req = { .type = HASH_A_FILE, .pid = getpid() };
    strncpy(req.path, filepath, sizeof(req.path) - 1);
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    struct timespec start_time, end_time;
    clock_gettime(1, &start_time);

    if (send_request(REQ_FIFO_PATH, req) == -1) {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n");
        unlink(response_fifo_path);
        return -1;
    }
   
    int resp_fd = open_for_reading(response_fifo_path);
    if (resp_fd == -1) { perror(BOLD RED"[CLIENT][ERRORE] open for reading"RES"\n"); unlink(response_fifo_path); return -1; }
    
    struct pollfd fds[1];
    fds[0].fd = resp_fd;
    fds[0].events = POLLIN;
    int poll_result = poll(fds, 1, 10000); 
    if (poll_result <= 0) {
        if (poll_result == 0) {
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Il server ha impiegato troppo tempo per rispondere"RES"\n");
        } else {
            perror(BOLD RED"poll"RES"\n");
        }
        close(resp_fd);
        unlink(response_fifo_path);
        return -1;
    }
    
    response_t resp;
    if (read_message(resp_fd, &resp, sizeof(resp)) == -1) {
        perror(BOLD RED"[CLIENT][ERRORE] read message"RES"\n");
        close(resp_fd);
        unlink(response_fifo_path);
        return -1;
    }
    close(resp_fd);
    unlink(response_fifo_path);
    
    clock_gettime(1, &end_time);
    double elapsed = elapsed_time(start_time, end_time);
    
    switch (resp.type) {
        case SEND_HASH:
            printf(BOLD BLUE"[CLIENT][INFO] File: %s"RES"\n", filepath);
            printf(BOLD BLUE"[CLIENT][INFO] Hash: %s"RES"\n", resp.hash);
            printf(BOLD BLUE"[CLIENT][INFO] Time: %.4f ms"RES"\n", elapsed * 1000);
            return 0;
            
        case SEND_ERROR:
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] %s (errore: %d)"RES"\n", resp.message, resp.error_code);
            return -1;
            
        default:
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Unknown Type: %d"RES"\n", resp.type);
            return -1;
    }
}

int send_terminate_request(void) {
    char response_fifo_path[PATH_MAX_LEN];
    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
   
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }

    request_t req = { .type = CLOSE_SERVER, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    if (send_request(REQ_FIFO_PATH, req) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n"); unlink(response_fifo_path); return -1; }

    unlink(response_fifo_path);
    printf(BOLD BLUE"[CLIENT][INFO] E' stata inviata la richiesta di chiusura al server"RES"\n");
    return 0;
}

int send_stats_request(void) {
    char response_fifo_path[PATH_MAX_LEN];

    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }
    
    request_t req = { .type = GET_STATISTICS, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    if (send_request(REQ_FIFO_PATH, req) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n"); unlink(response_fifo_path); return -1; }
    
    response_t resp;
    if (read_response(response_fifo_path, &resp) == -1) { perror(BOLD RED"[CLIENT][ERRORE] read response"RES"\n"); unlink(response_fifo_path); return -1; }
    unlink(response_fifo_path);
    
    if (resp.type == SEND_STATISTICS) {
        printf(BOLD BLUE"[CLIENT][INFO] Statistiche:"RES"\n"); 
        printf(BOLD BLUE"[CLIENT][INFO] Total requests: %lu"RES"\n", resp.stats.num_requests);
        printf(BOLD BLUE"[CLIENT][INFO] Cache hits: %lu"RES"\n", resp.stats.cache_hits);
        printf(BOLD BLUE"[CLIENT][INFO] Cache misses: %lu"RES"\n", resp.stats.cache_misses);
        printf(BOLD BLUE"[CLIENT][INFO] Files processed: %lu"RES"\n", resp.stats.num_processed);
        printf(BOLD BLUE"[CLIENT][INFO] Average processing time: %.3f ms"RES"\n", resp.stats.average_proc_time * 1000.0);
        return 0; 
    } else if (resp.type == SEND_ERROR) {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] statistiche: %s"RES"\n", resp.message);
        return -1;
    } else {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Unknown Type: %d"RES"\n", resp.type);
        return -1;
    }
}

void client_help(const char* name) {
    printf("Utilizzo: %s <opzioni>\n", name);
    printf("  -h, --help                 Mostra questo messaggio di errore\n");
    printf("  -s, --statistiche          Mostra le statistiche del server\n");
    printf("  -c, --chiudi               Chiudi il server\n");
    printf("  -p <file> o --path <file>  Richiedi l'hash SHA256 del file\n");

    printf("ESEMPIO: ./bin/client -p file1.txt -p file2.txt -s \n");
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"path",         required_argument, 0, 'p'},
        {"statistiche",  no_argument,       0, 's'},
        {"chiudi",       no_argument,       0, 'c'},
        {0,              0,                 0,  0 }
    };

    if (argc < 2) { client_help(argv[0]); return 1; }

    while ((opt = getopt_long(argc, argv, "hp:sc", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': { 
                char abs_path[4096];
                char* filepath = optarg; 

                if (realpath(filepath, abs_path) == NULL) { perror(BOLD RED"[CLIENT][ERRORE] realpath"RES" "); return 1; }

                if (strlen(abs_path) >= PATH_MAX_LEN) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Il percorso è troppo lungo"RES"\n"); return 1; }

                if (send_hash_request(abs_path) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Invio Richiesta Hash fallito per %s"RES"\n", abs_path); return 1; }
                break;
            }
            case 'h': client_help(argv[0]); return 0;
            case 's': return send_stats_request();
            case 'c': return send_terminate_request();
            case '?': client_help(argv[0]); return 1;
            default:
                abort();
        }
    }

    if (optind < argc) {fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Trovati argomenti non validi:"RES"\n");while (optind < argc) { fprintf(stderr, BOLD RED" -> %s"RES"\n", argv[optind++]); }return 1;}

    return 0;
}