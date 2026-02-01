#include "server_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

server_ctx_t* g_server_ctx = NULL;

int main(int argc, char* argv[]) {

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    int num_workers = DEFAULT_WORKERS;
    int order = ORDER_ASC;
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
                num_workers = atoi(optarg);
                if (num_workers <= 0 || num_workers > MAX_THREADS) {
                    fprintf(stderr, "Errore: workers deve essere tra 1 e %d\n", MAX_THREADS);
                    return 1;
                }
                break;
            case 'o':
                if (strcmp(optarg, "asc") == 0) {
                    order = ORDER_ASC;
                } else if (strcmp(optarg, "desc") == 0) {
                    order = ORDER_DESC;
                } else {
                    fprintf(stderr, "Errore: order deve essere 'asc' o 'desc'\n");
                    return 1;
                }
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                print_usage(argv[0]);
                return 1;
            default:
                abort();
        }
    }

    server_ctx_t ctx;
    g_server_ctx = &ctx;

    if (server_init(&ctx, num_workers, order) == -1) { fprintf(stderr, "Failed to initialize server\n"); return 1; }
    int result = server_run(&ctx);

    server_destroy(&ctx);
    unlink(REQUEST_FIFO_PATH);
    return result;
}
