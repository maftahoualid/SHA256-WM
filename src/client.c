#include "common.h"         // Inclusione header condiviso (strutture messaggi, costanti)
#include <stdio.h>          // Inclusione libreria I/O standard (printf, fprintf)
#include <stdlib.h>         // Inclusione libreria standard (exit, malloc)
#include <string.h>         // Inclusione libreria stringhe (strncpy, strcmp, strtok_r)
#include <unistd.h>         // Inclusione primitive POSIX (unlink, getpid, close)
#include <time.h>           // Inclusione funzioni tempo (clock_gettime, struct timespec)
#include <sys/select.h>     // Inclusione per select() (gestione timeout I/O)
#include <errno.h>          // Inclusione gestione codici errore

int send_hash_request(const char* filepath) { // Funzione per inviare richiesta calcolo hash
    char resp_fifo[MAX_PATH_LEN]; // Buffer per il percorso della FIFO di risposta privata
    // Formatta il nome della FIFO usando il PID del client per unicità (es. /tmp/sha256_resp_1234)
    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());

    // Crea la FIFO di risposta (o controlla se esiste). Se fallisce, ritorna -1
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }

    // Inizializza la struttura richiesta con tipo HASH e PID corrente
    request_msg_t req = { .type = REQ_HASH_FILE, .client_pid = getpid() };
    // Copia il percorso del file nel messaggio (troncando se necessario)
    strncpy(req.path, filepath, sizeof(req.path) - 1);
    // Copia il percorso della FIFO di risposta nel messaggio
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);

    struct timespec start_time, end_time; // Variabili per misurare il tempo (client-side latency)
    clock_gettime(CLOCK_MONOTONIC, &start_time); // Avvia il cronometro

    // Invia la richiesta alla FIFO pubblica del server.
    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        // Se l'invio fallisce (es. server spento/FIFO inesistente), stampa errore
        fprintf(stderr, "Error: Cannot connect to server! Is the server running?\n");
        unlink(resp_fifo); // Rimuove la FIFO creata inutilmente
        return -1; // Ritorna errore
    }
    
    // Apre la propria FIFO in lettura per attendere la risposta
    int resp_fd = open_fifo_read(resp_fifo);
    // Se apertura fallisce (errore sistema), stampa errore, pulisce e esce
    if (resp_fd == -1) { perror("open response FIFO"); unlink(resp_fifo); return -1; }
    
    fd_set readfds; // Insieme di File Descriptor per la select
    struct timeval timeout; // Struttura per definire il tempo massimo di attesa
    FD_ZERO(&readfds); // Azzera il set
    FD_SET(resp_fd, &readfds); // Aggiunge il file descriptor della FIFO al set
    timeout.tv_sec = 10; // Imposta timeout a 10 secondi
    timeout.tv_usec = 0; // 0 microsecondi
    
    // Attende che il descrittore diventi leggibile o che scada il tempo
    int select_result = select(resp_fd + 1, &readfds, NULL, NULL, &timeout);
    if (select_result <= 0) { // Se 0 (timeout) o < 0 (errore)
        if (select_result == 0) { // Caso Timeout
            fprintf(stderr, "Timeout waiting for server response\n"); // Log timeout
        } else { // Caso Errore select
            perror("select"); // Log errore sistema
        }
        close(resp_fd); // Chiude FD
        unlink(resp_fifo); // Cancella FIFO
        return -1; // Ritorna errore
    }
    
    response_msg_t resp; // Struttura per contenere la risposta
    // Legge la risposta dalla FIFO. Se fallisce:
    if (read_exact(resp_fd, &resp, sizeof(resp)) == -1) {
        perror("read response"); // Log errore lettura
        close(resp_fd); // Chiude
        unlink(resp_fifo); // Pulisce
        return -1; // Errore
    }
    close(resp_fd); // Chiude FD dopo lettura successo
    unlink(resp_fifo); // Rimuove FIFO dal disco
    
    clock_gettime(CLOCK_MONOTONIC, &end_time); // Ferma cronometro
    double elapsed = get_time_diff(start_time, end_time); // Calcola delta T
    
    switch (resp.type) { // Analizza tipo risposta server
        case RESP_HASH: // Caso successo (Hash calcolato)
            printf("File: %s\n", filepath); // Stampa nome file
            printf("SHA-256: %s\n", resp.hash); // Stampa hash ricevuto
            printf("Time: %.3f ms\n", elapsed * 1000); // Stampa tempo totale (latenza)
            return 0; // Successo
            
        case RESP_ERROR: // Caso errore dal server (es. file non trovato)
            fprintf(stderr, "Error: %s (code: %d)\n", resp.error_msg, resp.error_code); // Stampa msg server
            return -1; // Errore
            
        default: // Caso risposta imprevista
            fprintf(stderr, "Unknown response type: %d\n", resp.type); // Log
            return -1; // Errore
    }
}

int send_terminate_request(void) { // Funzione per inviare comando di spegnimento
    char resp_fifo[MAX_PATH_LEN]; // Buffer percorso FIFO
    // Formatta percorso FIFO
    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    
    // Crea FIFO (necessaria per protocollo, anche se qui non aspettiamo risposta esplicita di conferma nel codice)
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }
    
    // Crea messaggio di tipo TERMINATE
    request_msg_t req = { .type = REQ_TERMINATE, .client_pid = getpid() };
    // Imposta path FIFO risposta
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);
    
    // Invia richiesta al server
    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, "Error: Cannot connect to server\n"); // Errore connessione
        unlink(resp_fifo); // Pulisce
        return -1; // Errore
    }

    unlink(resp_fifo); // Pulisce subito la FIFO (Fire and forget)
    printf("Termination request sent to server\n"); // Conferma utente
    return 0; // Successo
}

int send_stats_request(void) { // Funzione per richiedere statistiche
    char resp_fifo[MAX_PATH_LEN]; // Buffer FIFO
    // Formatta nome FIFO
    snprintf(resp_fifo, sizeof(resp_fifo), "%s%d", CLIENT_FIFO_PREFIX, getpid());
    
    // Crea FIFO
    if (ensure_fifo(resp_fifo, 0666) == -1) { return -1; }
    
    // Crea messaggio REQ_STATS
    request_msg_t req = { .type = REQ_STATS, .client_pid = getpid() };
    // Imposta FIFO risposta
    snprintf(req.resp_fifo, sizeof(req.resp_fifo), "%s", resp_fifo);
    
    // Invia richiesta
    if (send_request(REQUEST_FIFO_PATH, req) == -1) {
        fprintf(stderr, "Error: Cannot connect to server. Is the server running?\n"); // Errore
        unlink(resp_fifo); // Pulisce
        return -1; // Ritorna -1
    }
    
    response_msg_t resp; // Buffer risposta
    // Legge la risposta (qui usa read_response che è bloccante senza select, assumendo server veloce)
    if (read_response(resp_fifo, &resp) == -1) {
        perror("read response"); // Errore lettura
        unlink(resp_fifo); // Pulisce
        return -1; // Ritorna -1
    }
    
    unlink(resp_fifo); // Rimuove FIFO dopo aver ricevuto i dati
    
    if (resp.type == RESP_STATS) { // Se la risposta è di tipo STATS
        printf("=== Server Statistics ===\n"); // Intestazione
        
        char* stats_str = resp.error_msg; // Il server mette le stats stringificate nel campo error_msg
        char* token; // Puntatore per tokenizzazione
        char* saveptr; // Puntatore di stato per strtok_r (thread-safe)
        
        // Tokenizza la stringa separata da virgole (es. "Requests:10,Hits:5...")
        token = strtok_r(stats_str, ",", &saveptr);
        while (token) { // Ciclo su tutti i token
            // Parsing manuale delle stringhe chiave-valore
            if (strncmp(token, "Requests:", 9) == 0) printf("Total requests: %s\n", token + 9);
            else if (strncmp(token, "Hits:", 5) == 0) printf("Cache hits: %s\n", token + 5);
            else if (strncmp(token, "Misses:", 7) == 0) printf("Cache misses: %s\n", token + 7);
            else if (strncmp(token, "Processed:", 10) == 0) printf("Files processed: %s\n", token + 10);
            else if (strncmp(token, "AvgTime:", 8) == 0) printf("Average processing time: %s ms\n", token + 8);
            token = strtok_r(NULL, ",", &saveptr); // Avanza al prossimo token
        }
        
        printf("========================\n"); // Chiusura
        return 0; // Successo
    } else if (resp.type == RESP_ERROR) { // Se il server risponde picche
        fprintf(stderr, "Error getting stats: %s\n", resp.error_msg); // Stampa errore
        return -1; // Fail
    } else { // Risposta ignota
        fprintf(stderr, "Unknown response type: %d\n", resp.type); // Log
        return -1; // Fail
    }
}

int main(int argc, char* argv[]) { // Funzione principale
    if (argc < 2) { // Controllo argomenti minimi (almeno 1 opzione o file)
        print_usage(argv[0]); // Stampa help
        return 1; // Exit error
    }
    
    // Itera sugli argomenti (gestione manuale invece di getopt per semplicità mista a path posizionali)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { // Flag Help
            print_usage(argv[0]); // Stampa
            return 0; // Exit success
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--stats") == 0) { // Flag Stats
            return send_stats_request(); // Invia richiesta stats e esce con il suo codice ritorno
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--terminate") == 0) { // Flag Terminate
            return send_terminate_request(); // Invia richiesta term e esce
        } else if (argv[i][0] == '-') { // Se inizia con - ma non è riconosciuto
            fprintf(stderr, "Unknown option: %s\n", argv[i]); // Errore
            print_usage(argv[0]); // Help
            return 1; // Exit error
        } else { // Altrimenti è un percorso file
            char* filepath = argv[i]; // Punta all'argomento
            char abs_path[4096]; // Buffer per path assoluto
            // Converte path relativo in assoluto (necessario perché server ha CWD diversa)
            if (realpath(filepath, abs_path) == NULL) { perror("realpath"); return 1; }
            filepath = abs_path; // Aggiorna puntatore
            // Check lunghezza massima path supportata dal protocollo
            if (strlen(abs_path) >= MAX_PATH_LEN) { fprintf(stderr, "Errore: Il percorso è troppo lungo"); return 1; }
            // Invia richiesta hash per il file
            if (send_hash_request(filepath) == -1) { fprintf(stderr, "Errore: Invio Richiesta Hash fallito"); return 1; }
        }
    }
    return 0; // Uscita normale se loop finito
}