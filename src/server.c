#include "server_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

server_t* server_varglobale = NULL;

int main(int argc, char* argv[]) {

    signal(SIGINT, gestore_segnali);
    signal(SIGTERM, gestore_segnali);
    signal(SIGPIPE, SIG_IGN);

    int numero_thread = DEFAULT_WORKERS;
    int ordine_coda = ORDER_ASC;
    int opt;

    static struct option long_options[] = {
        {"workers", required_argument, 0, 'w'},
        {"order",   required_argument, 0, 'o'},
        {"help",    no_argument,       0, 'h'},
        {0,         0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "w:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'w':
                numero_thread = atoi(optarg);

                if (numero_thread <= 0 || numero_thread > MAX_THREADS) {
                    fprintf(stderr, "Errore: workers deve essere tra 1 e %d\n", MAX_THREADS);
                    return 1;
                }
                break;
            case 'o':
                if (strcmp(optarg, "asc") == 0) {
                    ordine_coda = ORDER_ASC;
                } else if (strcmp(optarg, "desc") == 0) {
                    ordine_coda = ORDER_DESC;
                } else {
                    fprintf(stderr, "Errore: order deve essere 'asc' o 'desc'\n");
                    return 1;
                }
                break;
            case 'h':
                stampa_menu(argv[0]);
                return 0;
            case '?':
                stampa_menu(argv[0]);
                return 1;
            default:
                abort();
        }
    }

    server_t server;
    server_varglobale = &server;


    if (inizializza_server(&server, numero_thread, ordine_coda) == -1) { 
        fprintf(stderr, "Failed to initialize server\n");
        return 1;
    }
    

    int result = esegui_server(&server);

    chiudi_server(&server);
    unlink(PATH_FIFO_RICHIESTA);
    return result;
}