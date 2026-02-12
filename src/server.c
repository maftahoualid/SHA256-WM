#include "server_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

server_t* g_server = NULL;

int main(int argc, char* argv[]) {

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    int errno = 0;
    char* endptr;
    setvbuf(stdout, NULL, _IONBF, 0);

    int n_threads = DEFAULT_THREADS;
    int sched_order = ASCENDANT;

    int opt;
    static struct option long_options[] = {
        {"threads",     required_argument, 0, 't'},
        {"order",       required_argument, 0, 'o'},
        {"help",        no_argument,       0, 'h'},
        {0,             0,                 0,  0 }
    };


    while ((opt = getopt_long(argc, argv, "t:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                n_threads = strtol(optarg, &endptr, 10);
                EXIT_IF(errno != 0 || *endptr != '\0' || n_threads <= 0 || n_threads > MAX_THREADS, "[SERVER][ERRORE] Numero thread non valido (1-%d): %s", MAX_THREADS, optarg);
                break;
            case 'o':
                if (strcmp(optarg, "asc") == 0) sched_order = ASCENDANT;
                else if (strcmp(optarg, "desc") == 0) sched_order = DESCENDANT;
                else FATAL("[SERVER][ERRORE] L'ordine deve essere 'asc' o 'desc'\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                FATAL("[SERVER][ERRORE] Parametro non valido\n");
            default:
                abort();
        }
    }

    server_t server;
    g_server = &server;
    EXIT_IF(init_server(&server, n_threads, sched_order) == -1, "[SERVER][ERRORE] Inizializzazione server fallita");
    int s = run_server(&server);
    close_server(&server);
    unlink(REQUEST_FIFO_PATH);
    return s;
}