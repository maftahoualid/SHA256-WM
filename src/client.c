// Includiamo il file comune che contiene le definizioni delle struct (request_t, response_t) e i colori
#include "common.h"
// Libreria standard per input/output (printf, snprintf, ecc.)
#include <stdio.h>
// Libreria standard per allocazione memoria e conversioni (exit, strtol)
#include <stdlib.h>
// Libreria per manipolare stringhe (strlen, strcpy, ecc.)
#include <string.h>
// Libreria per chiamate di sistema POSIX (unistd.h gestisce read, write, close, unlink, getpid)
#include <unistd.h>
// Libreria per gestire il tempo (clock_gettime per misurare i millisecondi)
#include <time.h>
// Libreria FONDAMENTALE per il nostro "trucco" del timeout: permette di aspettare un evento su un file
#include <poll.h>
// Libreria per gestire i codici di errore (errno)
#include <errno.h>
// Libreria per leggere gli argomenti da riga di comando (getopt_long per gestire -p, -s, ecc.)
#include <getopt.h>
// Libreria per controllare le modalità di apertura dei file (O_RDONLY, O_NONBLOCK) - Aggiunta nel fix precedente
#include <fcntl.h>

// -------------------------------------------------------------------------------------
// FUNZIONE: send_hash_request
// Questa è la funzione principale. Chiede al server di calcolare l'hash di un file specifico.
// Restituisce 0 se tutto va bene, -1 se c'è un errore.
// -------------------------------------------------------------------------------------
int send_hash_request(const char* filepath) {
    // Buffer per contenere il percorso della FIFO su cui riceveremo la risposta
    char response_fifo_path[PATH_MAX_LEN];

    // Costruiamo il nome della FIFO di risposta usando il PID (Process ID) del client.
    // Esempio: se il mio PID è 1234, la stringa diventa "/tmp/hash_client_1234".
    // Questo serve a non confondersi con altri client attivi contemporaneamente.
    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
    
    // Creiamo fisicamente questo file FIFO sul disco. 0777 sono i permessi (lettura/scrittura per tutti).
    // Se fallisce, ritorniamo errore.
    if (create_fifo(response_fifo_path, 0777) == -1) { return -1; }

    // Prepariamo la struttura della richiesta (il pacchetto da inviare)
    request_t req = { .type = HASH_A_FILE, .pid = getpid() }; // Tipo: HASH, PID: il mio ID
    
    // Copiamo il percorso del file da analizzare dentro la struttura richiesta
    strncpy(req.path, filepath, sizeof(req.path) - 1);
    
    // Copiamo anche il nome della FIFO dove vogliamo ricevere la risposta
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    
    // Variabili per il cronometro (misurare quanto tempo ci mette il server)
    struct timespec start_time, end_time;
    // Facciamo partire il cronometro ora
    clock_gettime(1, &start_time); // 1 sta per CLOCK_MONOTONIC

    // Spediamo la richiesta al server sulla FIFO pubblica (/tmp/hash_server)
    if (send_request(REQ_FIFO_PATH, req) == -1) {
        // Se non riusciamo a spedire (es. server spento), stampiamo errore
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n");
        // Cancelliamo la nostra FIFO temporanea per non lasciare spazzatura
        unlink(response_fifo_path);
        return -1;
    }
   
    // --- INIZIO LOGICA "ANTI-BLOCCO" (La parte ristrutturata) ---
    
    // Apriamo la nostra FIFO di risposta in lettura (O_RDONLY) ma in modalità NON-BLOCCANTE (O_NONBLOCK).
    // Normalmente, aprire una FIFO in lettura blocca il programma finché qualcuno non scrive.
    // Noi NON vogliamo bloccarci subito, vogliamo avere il controllo.
    int resp_fd = open(response_fifo_path, O_RDONLY | O_NONBLOCK);
    
    // Se l'apertura fallisce, errore.
    if (resp_fd == -1) { perror(BOLD RED"[CLIENT][ERRORE] open FIFO"RES"\n"); unlink(response_fifo_path); return -1; }
    
    // Prepariamo la struttura per la funzione poll(). Poll serve a "sorvegliare" un file.
    struct pollfd fds[1];
    fds[0].fd = resp_fd;      // Sorveglia il file descriptor della nostra FIFO
    fds[0].events = POLLIN;   // Avvisaci se c'è qualcosa da leggere (POLLIN = Poll Input)
    
    // Chiamiamo poll(). Questa funzione aspetta al massimo 10000 millisecondi (10 secondi).
    int poll_result = poll(fds, 1, 10000); 
    
    // Se poll ritorna 0 (timeout scaduto) o -1 (errore)
    if (poll_result <= 0) {
        if (poll_result == 0) fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Timeout server"RES"\n");
        else perror(BOLD RED"poll"RES"\n");
        
        // Chiudiamo il file e cancelliamo la FIFO
        close(resp_fd);
        unlink(response_fifo_path);
        return -1;
    }
    
    // Se siamo qui, c'è qualcosa da leggere!
    // Usiamo fdopen per trasformare il "file descriptor" grezzo (int) in uno stream standard C (FILE*).
    // Questo ci permette di usare la comoda funzione fread() invece di read().
    FILE* stream = fdopen(resp_fd, "rb");
    
    // Creiamo la variabile per ospitare la risposta
    response_t resp;
    
    // Leggiamo la risposta dallo stream. fread gestisce buffer e dettagli per noi.
    // Chiede di leggere 1 elemento grande quanto sizeof(response_t).
    if (fread(&resp, sizeof(response_t), 1, stream) != 1) {
        perror(BOLD RED"[CLIENT][ERRORE] Errore di lettura risposta"RES"\n");
        fclose(stream); // fclose chiude anche il fd sottostante
        unlink(response_fifo_path);
        return -1;
    }
    
    // Chiudiamo lo stream (che chiude anche il file)
    fclose(stream);
    // Cancelliamo la FIFO dal disco, non serve più
    unlink(response_fifo_path);
    
    // Fermiamo il cronometro
    clock_gettime(1, &end_time);
    // Calcoliamo la differenza di tempo
    double elapsed = elapsed_time(start_time, end_time);
    
    // Controlliamo cosa ci ha risposto il server
    switch (resp.type) {
        case SEND_HASH: // SUCCESSO!
            printf(BOLD BLUE"[CLIENT][INFO] File: %s"RES"\n", filepath);
            printf(BOLD BLUE"[CLIENT][INFO] Hash: %s"RES"\n", resp.hash);
            printf(BOLD BLUE"[CLIENT][INFO] Time: %.4f ms"RES"\n", elapsed * 1000);
            return 0;
            
        case SEND_ERROR: // IL SERVER HA AVUTO UN PROBLEMA (es. file non trovato)
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] %s (errore: %d)"RES"\n", resp.message, resp.error_code);
            return -1;
            
        default: // RISPOSTA INCOMPRENSIBILE
            fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Unknown Type: %d"RES"\n", resp.type);
            return -1;
    }
}

// -------------------------------------------------------------------------------------
// FUNZIONE: send_terminate_request
// Invia al server il comando di spegnersi (opzione -c).
// -------------------------------------------------------------------------------------
int send_terminate_request(void) {
    char response_fifo_path[PATH_MAX_LEN];
    // Solito rituale: costruiamo il nome della FIFO univoca
    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
   
    // La creiamo (anche se per la chiusura il server non ci risponde, serve per protocollo)
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }

    // Prepariamo la richiesta di tipo CLOSE_SERVER
    request_t req = { .type = CLOSE_SERVER, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    
    // La spediamo
    if (send_request(REQ_FIFO_PATH, req) == -1) { 
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n"); 
        unlink(response_fifo_path); 
        return -1; 
    }

    // Cancelliamo subito la FIFO, tanto il server si sta spegnendo e non ci risponderà
    unlink(response_fifo_path);
    printf(BOLD BLUE"[CLIENT][INFO] E' stata inviata la richiesta di chiusura al server"RES"\n");
    return 0;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: send_stats_request
// Chiede al server le statistiche (opzione -s).
// -------------------------------------------------------------------------------------
int send_stats_request(void) {
    char response_fifo_path[PATH_MAX_LEN];

    // Crea la FIFO per ricevere i numeri
    snprintf(response_fifo_path, sizeof(response_fifo_path), "%s%d", CLIENT_FIFO_PATH, getpid());
    if (create_fifo(response_fifo_path, 0666) == -1) { return -1; }
    
    // Prepara la richiesta GET_STATISTICS
    request_t req = { .type = GET_STATISTICS, .pid = getpid() };
    snprintf(req.response_fifo_path, sizeof(req.response_fifo_path), "%s", response_fifo_path);
    
    // Invia
    if (send_request(REQ_FIFO_PATH, req) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Non è stato possibile contattare il server"RES"\n"); unlink(response_fifo_path); return -1; }
    
    response_t resp;
    // Qui usiamo la funzione read_response semplice (da common.c) invece del polling complesso.
    // Perché? Le statistiche sono istantanee da recuperare (sono variabili in memoria RAM), 
    // quindi non rischiamo blocchi lunghi come per il calcolo dell'hash di un file enorme.
    if (read_response(response_fifo_path, &resp) == -1) { perror(BOLD RED"[CLIENT][ERRORE] read response"RES"\n"); unlink(response_fifo_path); return -1; }
    
    // Pulizia
    unlink(response_fifo_path);
    
    // Stampiamo i risultati
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

// -------------------------------------------------------------------------------------
// FUNZIONE: client_help
// Stampa il messaggio di aiuto se l'utente sbaglia o chiede aiuto.
// -------------------------------------------------------------------------------------
void client_help(const char* name) {
    printf("Utilizzo: %s <opzioni>\n", name);
    printf("  -h, --help                 Mostra questo messaggio di errore\n");
    printf("  -s, --statistiche          Mostra le statistiche del server\n");
    printf("  -c, --chiudi               Chiudi il server\n");
    printf("  -p <file> o --path <file>  Richiedi l'hash SHA256 del file\n");

    printf("ESEMPIO: ./bin/client -p file1.txt -p file2.txt -s \n");
}

// -------------------------------------------------------------------------------------
// FUNZIONE: main
// Punto di ingresso del programma client.
// -------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // Disabilita il buffering dell'output. Significa: "appena fai printf, scrivi subito a schermo".
    // Serve per vedere i log in tempo reale senza ritardi.
    setvbuf(stdout, NULL, _IONBF, 0);
    
    int opt;
    int option_index = 0;
    
    // Definizione delle opzioni lunghe per getopt_long (es. --path invece di -p)
    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'}, // non vuole argomenti
        {"path",         required_argument, 0, 'p'}, // vuole un argomento (il file)
        {"statistiche",  no_argument,       0, 's'},
        {"chiudi",       no_argument,       0, 'c'},
        {0,              0,                 0,  0 }  // Terminatore array
    };

    // Se l'utente lancia solo "./client" senza niente, mostra aiuto ed esci.
    if (argc < 2) { client_help(argv[0]); return 1; }

    // Ciclo che legge tutti gli argomenti passati da riga di comando uno per uno
    while ((opt = getopt_long(argc, argv, "hp:sc", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p': { // Caso -p o --path
                char abs_path[4096];
                char* filepath = optarg; // optarg contiene il nome del file passato dall'utente

                // realpath converte un percorso relativo (es. "../file.txt") in assoluto (es. "/home/user/file.txt")
                // È fondamentale perché il server potrebbe girare in una cartella diversa!
                if (realpath(filepath, abs_path) == NULL) { perror(BOLD RED"[CLIENT][ERRORE] realpath"RES" "); return 1; }

                // Controllo sicurezza lunghezza
                if (strlen(abs_path) >= PATH_MAX_LEN) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Il percorso è troppo lungo"RES"\n"); return 1; }

                // Chiama la funzione che fa tutto il lavoro sporco
                if (send_hash_request(abs_path) == -1) { fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Invio Richiesta Hash fallito per %s"RES"\n", abs_path); return 1; }
                break;
            }
            case 'h': client_help(argv[0]); return 0;
            case 's': return send_stats_request();
            case 'c': return send_terminate_request();
            case '?': // Opzione non riconosciuta
                client_help(argv[0]); return 1;
            default:
                abort(); // Errore grave imprevisto
        }
    }

    // Se sono rimasti argomenti che non sono opzioni (es. "./client file.txt" senza -p davanti)
    if (optind < argc) {
        fprintf(stderr, BOLD RED"[CLIENT][ERRORE] Trovati argomenti non validi:"RES"\n");
        while (optind < argc) { fprintf(stderr, BOLD RED" -> %s"RES"\n", argv[optind++]); }
        return 1;
    }

    return 0;
}