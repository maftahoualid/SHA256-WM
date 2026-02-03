#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <getopt.h>

int chiedi_hash(const char* path) {
    char fifo_risposta[MAX_PATH_LEN];

    snprintf(fifo_risposta, sizeof(fifo_risposta), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (crea_fifo(fifo_risposta, 0666) == -1) { return -1; }
    messaggio_richiesta_t richiesta = { .tipo = REQ_HASH_FILE, .pid_client = getpid() };
    strncpy(richiesta.path, path, sizeof(richiesta.path) - 1);
    snprintf(richiesta.fifo_risposta, sizeof(richiesta.fifo_risposta), "%s", fifo_risposta);
    struct timespec inizio, fine;
    clock_gettime(1, &inizio);

    if (invia_richiesta(PATH_FIFO_RICHIESTA, richiesta) == -1) {
        fprintf(stderr, "Error: Cannot connect to server! Is the server running?\n");
        unlink(fifo_risposta);
        return -1;
    }
   
    int resp_fd = apri_fifo_lettura(fifo_risposta);
    if (resp_fd == -1) { perror("open response FIFO"); unlink(fifo_risposta); return -1; }
    
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
        unlink(fifo_risposta);
        return -1;
    }
    
    messaggio_risposta_t risposta;
    if (leggi_da_fifo(resp_fd, &risposta, sizeof(risposta)) == -1) {
        perror("read response");
        close(resp_fd);
        unlink(fifo_risposta);
        return -1;
    }
    close(resp_fd);
    unlink(fifo_risposta);
    
    clock_gettime(1, &fine);
    double tempo_trascorso = differenza(inizio, fine);
    
    switch (risposta.tipo) {
        case RESP_HASH:
            printf("File: %s\n", path);
            printf("SHA-256: %s\n", risposta.hash);
            printf("Time: %.3f ms\n", tempo_trascorso * 1000);
            return 0;
            
        case RESP_ERROR:
            fprintf(stderr, "Error: %s (code: %d)\n", risposta.messaggio, risposta.codice);
            return -1;
            
        default:
            fprintf(stderr, "Unknown response type: %d\n", risposta.tipo);
            return -1;
    }
}

int chiedi_chiusura_server(void) {
    char fifo_risposta[MAX_PATH_LEN];
    snprintf(fifo_risposta, sizeof(fifo_risposta), "%s%d", CLIENT_FIFO_PREFIX, getpid());
   
    if (crea_fifo(fifo_risposta, 0666) == -1) { return -1; }

    messaggio_richiesta_t richiesta = { .tipo = REQ_TERMINATE, .pid_client = getpid() };
    snprintf(richiesta.fifo_risposta, sizeof(richiesta.fifo_risposta), "%s", fifo_risposta);
    if (invia_richiesta(PATH_FIFO_RICHIESTA, richiesta) == -1) { fprintf(stderr, "Error: Cannot connect to server\n"); unlink(fifo_risposta); return -1; }

    unlink(fifo_risposta);
    printf("Termination request sent to server\n");
    return 0;
}

int chiedi_statistiche(void) {
    char fifo_risposta[MAX_PATH_LEN];

    snprintf(fifo_risposta, sizeof(fifo_risposta), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    if (crea_fifo(fifo_risposta, 0666) == -1) { return -1; }
    
    messaggio_richiesta_t richiesta = { .tipo = REQ_STATS, .pid_client = getpid() };
    snprintf(richiesta.fifo_risposta, sizeof(richiesta.fifo_risposta), "%s", fifo_risposta);
    if (invia_richiesta(PATH_FIFO_RICHIESTA, richiesta) == -1) { fprintf(stderr, "Error: Cannot connect to server. Is the server running?\n"); unlink(fifo_risposta); return -1; }
    
    messaggio_risposta_t risposta;
    if (leggi_risposta(fifo_risposta, &risposta) == -1) { perror("read response"); unlink(fifo_risposta); return -1; }
    unlink(fifo_risposta);
    
    if (risposta.tipo == RESP_STATS) {
        printf("=== Server Statistics ===\n"); 
        printf("Total requests: %lu\n", risposta.statistiche.richieste_totali);
        printf("Cache hits: %lu\n", risposta.statistiche.cache_hits);
        printf("Cache misses: %lu\n", risposta.statistiche.cache_misses);
        printf("Files processed: %lu\n", risposta.statistiche.file_processati);
        printf("Average processing time: %.3f ms\n", risposta.statistiche.media_tempo_processamento * 1000.0);
        printf("========================\n"); 
        return 0; 
    } else if (risposta.tipo == RESP_ERROR) {
        fprintf(stderr, "Error getting stats: %s\n", risposta.messaggio);
        return -1;
    } else {
        fprintf(stderr, "Unknown response type: %d\n", risposta.tipo);
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

    if (argc < 2) { stampa_menu(argv[0]); return 1; }

    while ((opt = getopt_long(argc, argv, "hp:st", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': { 
                char abs_path[4096];
                char* path = optarg; 

                if (realpath(path, abs_path) == NULL) { perror("Errore realpath"); return 1; }

                if (strlen(abs_path) >= MAX_PATH_LEN) { fprintf(stderr, "Errore: Il percorso è troppo lungo\n"); return 1; }

                if (chiedi_hash(abs_path) == -1) { fprintf(stderr, "Errore: Invio Richiesta Hash fallito per %s\n", abs_path); return 1; }
                break;
            }
            case 'h': stampa_menu(argv[0]); return 0;
            case 's': return chiedi_statistiche();
            case 't': return chiedi_chiusura_server();
            case '?': stampa_menu(argv[0]); return 1;
            default:
                abort();
        }
    }

    if (optind < argc) {fprintf(stderr, "Errore: Trovati argomenti non validi:\n");while (optind < argc) { fprintf(stderr, " -> %s\n", argv[optind++]); }return 1;}

    return 0;
}