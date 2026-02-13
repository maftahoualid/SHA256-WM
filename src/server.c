#include "server_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

server_t* g_server = NULL;

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    int errno = 0;
    char* endptr;

    int n_threads = DEFAULT_THREADS_NUM;
    int sched_order = ASCENDING;

    int opt;
    static struct option long_options[] = {
        {"threads",     required_argument, 0, 't'},
        {"ordine",      required_argument, 0, 'o'},
        {"help",        no_argument,       0, 'h'},
        {0,             0,                 0,  0 }
    };


    while ((opt = getopt_long(argc, argv, "t:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                n_threads = strtol(optarg, &endptr, 10);
                EXIT_IF(errno != 0 || *endptr != '\0' || n_threads <= 0 || n_threads > MAX_THREADS_NUM, BOLD RED"[SERVER] Numero thread non valido (1-%d): %s"RES, MAX_THREADS_NUM, optarg);
                break;
            case 'o':
                if (strcmp(optarg, "asc") == 0) sched_order = ASCENDING;
                else if (strcmp(optarg, "desc") == 0) sched_order = DESCENDING;
                else FATAL(BOLD RED"[SERVER] L'ordine deve essere 'asc' o 'desc'"RES"\n");
                break;
            case 'h':
                server_help(argv[0]);
                return 0;
            case '?':
                server_help(argv[0]);
                FATAL(BOLD RED"[SERVER] Parametro non valido"RES"\n");
            default:
                abort();
        }
    }

    server_t server;
    g_server = &server;
    EXIT_IF(init_server(&server, n_threads, sched_order) == -1, BOLD RED"[SERVER] Inizializzazione server fallita"RES"\n");
    int s = run_server(&server);
    close_server(&server);
    unlink(REQ_FIFO_PATH);
    return s;
}