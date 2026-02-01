#include "server_utils.h"   // Inclusione delle definizioni e funzioni di utilità del server
#include <stdio.h>          // Inclusione libreria I/O standard (printf, fprintf)
#include <stdlib.h>         // Inclusione libreria standard (atoi, exit, abort)
#include <string.h>         // Inclusione libreria stringhe (strcmp)
#include <unistd.h>         // Inclusione primitive POSIX (unlink, sleep)
#include <signal.h>         // Inclusione gestione segnali (signal, SIGINT, ecc.)
#include <getopt.h>         // Inclusione parsing argomenti riga di comando (getopt_long)

server_ctx_t* g_server_ctx = NULL; // Puntatore globale al contesto (necessario per signal handler)

int main(int argc, char* argv[]) { // Punto di ingresso, riceve argomenti da riga di comando

    signal(SIGINT, signal_handler);  // Registra gestore per CTRL+C (interruzione)
    signal(SIGTERM, signal_handler); // Registra gestore per terminazione (kill)
    signal(SIGPIPE, SIG_IGN);        // Ignora SIGPIPE per non crashare se il client chiude la connessione

    int num_workers = DEFAULT_WORKERS; // Imposta workers di default (definito in server_structs.h)
    int order = ORDER_ASC;             // Imposta ordine di default (crescente)
    int opt;                           // Variabile per memorizzare l'opzione corrente

    static struct option long_options[] = { // Definizione opzioni lunghe per getopt
        {"workers", required_argument, 0, 'w'}, // --workers richiede argomento, mappa a 'w'
        {"order",   required_argument, 0, 'o'}, // --order richiede argomento, mappa a 'o'
        {"help",    no_argument,       0, 'h'}, // --help non richiede argomento, mappa a 'h'
        {0,         0,                 0,  0 }  // Terminatore array (sentinella)
    };

    // Ciclo parsing argomenti finché ce ne sono
    while ((opt = getopt_long(argc, argv, "w:o:h", long_options, NULL)) != -1) {
        switch (opt) { // Switch sul carattere dell'opzione trovata
            case 'w': // Caso --workers o -w
                num_workers = atoi(optarg); // Converte l'argomento stringa in intero
                // Verifica che il numero di workers sia valido
                if (num_workers <= 0 || num_workers > MAX_THREADS) {
                    fprintf(stderr, "Errore: workers deve essere tra 1 e %d\n", MAX_THREADS); // Stampa errore
                    return 1; // Termina con errore
                }
                break; // Esce dallo switch
            case 'o': // Caso --order o -o
                if (strcmp(optarg, "asc") == 0) { // Se l'argomento è "asc"
                    order = ORDER_ASC; // Imposta costante ordine crescente
                } else if (strcmp(optarg, "desc") == 0) { // Se l'argomento è "desc"
                    order = ORDER_DESC; // Imposta costante ordine decrescente
                } else { // Qualsiasi altro valore è invalido
                    fprintf(stderr, "Errore: order deve essere 'asc' o 'desc'\n"); // Stampa errore
                    return 1; // Termina con errore
                }
                break; // Esce dallo switch
            case 'h': // Caso --help o -h
                print_usage(argv[0]); // Stampa guida uso
                return 0; // Termina con successo
            case '?': // Opzione non riconosciuta o argomento mancante
                print_usage(argv[0]); // Stampa guida uso
                return 1; // Termina con errore
            default: // Caso impossibile (sicurezza)
                abort(); // Interrompe esecuzione
        }
    }

    server_ctx_t ctx; // Alloca struttura contesto server sullo stack
    g_server_ctx = &ctx; // Assegna indirizzo al puntatore globale per i segnali

    // Inizializza server (coda, cache, thread). Ritorna -1 se fallisce.
    if (server_init(&ctx, num_workers, order) == -1) { 
        fprintf(stderr, "Failed to initialize server\n"); // Stampa errore inizializzazione
        return 1; // Termina con errore
    }
    
    // Avvia loop principale. Blocca finché running=true.
    int result = server_run(&ctx);

    server_destroy(&ctx); // Pulisce risorse, ferma thread e libera memoria
    unlink(REQUEST_FIFO_PATH); // Rimuove la FIFO dal file system
    return result; // Ritorna codice uscita (0 successo)
}