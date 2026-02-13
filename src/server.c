// Includiamo il nostro "coltellino svizzero" di utilità.
// Questo include a cascata anche server_structs.h e common.h, quindi abbiamo tutto.
#include "server_utils.h"
// Libreria standard per input/output (printf, ecc.)
#include <stdio.h>
// Libreria standard per conversioni numeriche (strtol, atoi) e gestione memoria
#include <stdlib.h>
// Libreria per manipolare stringhe (strcmp)
#include <string.h>
// Libreria POSIX per chiamate di sistema (unlink, close)
#include <unistd.h>
// Libreria fondamentale per catturare i segnali (CTRL+C, SIGTERM)
#include <signal.h>
// Libreria per leggere le opzioni da riga di comando in modo facile (getopt_long)
#include <getopt.h>

// --- VARIABILE GLOBALE ---
// Creiamo un puntatore globale alla struttura del server.
// Perché globale? Perché la funzione che gestisce i segnali (sig_handler) non accetta argomenti,
// quindi l'unico modo per fargli vedere il server e spegnerlo è usare una variabile globale.
server_t* g_server = NULL;

// -------------------------------------------------------------------------------------
// FUNZIONE: main
// Il punto di partenza di tutto il programma.
// -------------------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    // Disabilita il "buffering" di stdout.
    // In parole povere: "Appena faccio una printf, scrivi SUBITO sul terminale".
    // Senza questo, a volte i messaggi rimangono incastrati in memoria finché non c'è un "a capo".
    setvbuf(stdout, NULL, _IONBF, 0);

    // --- GESTIONE SEGNALI ---
    // Diciamo al sistema operativo: "Se l'utente preme CTRL+C (SIGINT), non uccidermi subito.
    // Esegui invece la funzione 'sig_handler' che ho scritto io in server_utils.c".
    signal(SIGINT, sig_handler);
    // Lo stesso vale per SIGTERM (il comando 'kill' generico).
    signal(SIGTERM, sig_handler);
    
    // IMPORTANTE: Ignoriamo il segnale SIGPIPE.
    // SIGPIPE succede se proviamo a scrivere su una Pipe (FIFO) e il client dall'altra parte è morto/crashato.
    // Di default, Linux ucciderebbe il server. Noi vogliamo solo che la 'fwrite' fallisca (ritorni errore),
    // ma il server deve rimanere vivo per servire gli altri client!
    signal(SIGPIPE, SIG_IGN);

    // Variabili per gestire gli errori e la lettura dei numeri
    int errno = 0;
    char* endptr;

    // --- VALORI DI DEFAULT ---
    // Se l'utente non specifica nulla, useremo 4 thread.
    int n_threads = DEFAULT_THREADS_NUM;
    // Se l'utente non specifica nulla, ordineremo i file dal più piccolo al più grande (ASCENDING).
    int sched_order = ASCENDING;

    // --- PARSING DEGLI ARGOMENTI (getopt) ---
    int opt;
    // Questa struttura dice a getopt quali comandi lunghi esistono.
    static struct option long_options[] = {
        {"threads",     required_argument, 0, 't'}, // --threads vuole un numero ('t')
        {"ordine",      required_argument, 0, 'o'}, // --ordine vuole una stringa ('o')
        {"help",        no_argument,       0, 'h'}, // --help non vuole argomenti ('h')
        {0,             0,                 0,  0 }  // Tappo finale per dire che l'array è finito
    };

    // Ciclo while che legge gli argomenti uno alla volta.
    // "t:o:h" significa:
    // - t è seguito da due punti (:), quindi vuole un parametro.
    // - o è seguito da due punti (:), quindi vuole un parametro.
    // - h non ha due punti, quindi è un interruttore semplice.
    while ((opt = getopt_long(argc, argv, "t:o:h", long_options, NULL)) != -1) {
        switch (opt) {
            
            // Caso -t o --threads
            case 't':
                // Convertiamo la stringa (optarg) in numero intero (base 10).
                n_threads = strtol(optarg, &endptr, 10);
                
                // Controllo errori paranoico:
                // 1. errno != 0: c'è stato un errore di conversione.
                // 2. *endptr != '\0': l'utente ha scritto spazzatura (es. "4thread" invece di "4").
                // 3. n_threads <= 0: non possiamo avere 0 o -5 thread.
                // 4. n_threads > MAX: non vogliamo esplodere la CPU (limite fissato a 8).
                // La macro EXIT_IF (da common.h) stampa l'errore ed esce se la condizione è vera.
                EXIT_IF(errno != 0 || *endptr != '\0' || n_threads <= 0 || n_threads > MAX_THREADS_NUM, BOLD RED"[SERVER] Numero thread non valido (1-%d): %s"RES, MAX_THREADS_NUM, optarg);
                break;
            
            // Caso -o o --ordine
            case 'o':
                // Se l'utente ha scritto "asc", impostiamo l'ordine crescente
                if (strcmp(optarg, "asc") == 0) sched_order = ASCENDING;
                // Se ha scritto "desc", decrescente
                else if (strcmp(optarg, "desc") == 0) sched_order = DESCENDING;
                // Altrimenti errore fatale
                else FATAL(BOLD RED"[SERVER] L'ordine deve essere 'asc' o 'desc'"RES"\n");
                break;
            
            // Caso -h o --help
            case 'h':
                server_help(argv[0]); // Stampa la guida
                return 0; // Esce pulito
            
            // Caso ?: Opzione sconosciuta
            case '?':
                server_help(argv[0]);
                FATAL(BOLD RED"[SERVER] Parametro non valido"RES"\n");
            
            // Caso impossibile (difensivo)
            default:
                abort();
        }
    }

    // --- AVVIO DEL SERVER ---
    
    // Creiamo la variabile "server" sullo stack (memoria locale del main).
    // Questa struttura conterrà TUTTO (coda, cache, thread, statistiche).
    server_t server;
    
    // Colleghiamo il puntatore globale a questa variabile locale.
    // Ora il sig_handler può vedere e modificare 'server'.
    g_server = &server;

    // Inizializziamo il server (allochiamo memoria per code, avviamo i thread, ecc.).
    // Se restituisce -1, stampiamo errore ed usciamo.
    EXIT_IF(init_server(&server, n_threads, sched_order) == -1, BOLD RED"[SERVER] Inizializzazione server fallita"RES"\n");
    
    // Facciamo partire il ciclo principale (infinito).
    // Il programma rimarrà bloccato dentro 'run_server' finché non decidiamo di spegnerlo.
    // 's' conterrà il valore di ritorno (di solito 0).
    int s = run_server(&server);

    // --- CHIUSURA E PULIZIA ---
    // Se siamo arrivati qui, significa che run_server è finito (es. comando di chiusura ricevuto).
    
    // Chiudiamo i thread, liberiamo la memoria della cache e della coda.
    close_server(&server);
    
    // Cancelliamo dal disco il file della FIFO pubblica (/tmp/hash_server)
    // così nessuno proverà più a scriverci.
    unlink(REQ_FIFO_PATH);

    // Restituiamo lo stato finale al sistema operativo.
    return s;
}