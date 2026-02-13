// Includiamo il file header "common.h" che contiene le definizioni comuni (struct, colori, macro)
#include "common.h"
// Libreria standard per input/output (printf, fopen, fread, fwrite)
#include <stdio.h>
// Libreria standard per la gestione della memoria e utilità generali
#include <stdlib.h>
// Libreria per la manipolazione delle stringhe (non usata molto qui, ma utile averla)
#include <string.h>
// Libreria POSIX per le chiamate di sistema (unistd sta per "Unix Standard"). Gestisce unlink, access, ecc.
#include <unistd.h>
// Libreria per il controllo dei file (File Control). Contiene definizioni come O_RDONLY, O_WRONLY.
#include <fcntl.h>
// Libreria per gestire gli errori. Ci permette di leggere la variabile globale 'errno' quando qualcosa va storto.
#include <errno.h>
// Libreria fondamentale per ottenere informazioni sui file (stat) e per i permessi (chmod)
#include <sys/stat.h>

// -------------------------------------------------------------------------------------
// FUNZIONE: create_fifo
// Questa funzione cerca di creare una Named Pipe (FIFO) sul disco.
// È robusta: se la FIFO esiste già, controlla che sia davvero una FIFO e non un file normale.
// Restituisce 0 se tutto ok, -1 se c'è un errore.
// -------------------------------------------------------------------------------------
int create_fifo(const char* path, mode_t mode) {
    // Proviamo a creare la FIFO usando la chiamata di sistema 'mkfifo'.
    // 'path' è il percorso (es. "/tmp/hash_server"), 'mode' sono i permessi (es. 0666).
    // Se mkfifo restituisce 0, significa "Successo! Ho creato il file".
    if (mkfifo(path, mode) == 0) return 0;

    // Se arriviamo qui, mkfifo ha fallito. Perché?
    // Se l'errore NON è "EEXIST" (File Exists), allora è un errore grave (es. disco pieno, permessi negati).
    if (errno != EEXIST) { 
        // Stampiamo l'errore e usciamo
        perror(BOLD RED"[ERRORE] mkfifo"); 
        return -1; 
    }

    // Se l'errore ERA "EEXIST", significa che il file c'è già.
    // Dobbiamo assicurarci che sia una FIFO e non un file di testo normale o una cartella.
    
    // Struttura 'stat' che conterrà le informazioni sul file
    struct stat st;

    // Chiamiamo 'stat' sul percorso. Se restituisce 0 (successo) E...
    // ...usiamo la macro S_ISFIFO per controllare se la modalità del file (st_mode) indica una FIFO...
    if (stat(path, &st) == 0 && S_ISFIFO(st.st_mode)) { 
        return 0; // ...allora va tutto bene, la FIFO esiste ed è valida. Ritorniamo successo.
    }

    // Se siamo qui, il file esiste ma NON è una FIFO (magari è una cartella con lo stesso nome).
    // Questo è un problema perché non possiamo usarlo per comunicare.
    fprintf(stderr, BOLD RED"[ERRORE] '%s' esiste e non è una FIFO."RES"\n", path);
    return -1;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: send_response
// Usata dal SERVER per inviare il risultato (response_t) al client.
// -------------------------------------------------------------------------------------
int send_response(const char* fifo, response_t resp) {
    // Apriamo la FIFO in modalità "Write Binary" ("wb").
    // 'w': scrittura. 'b': binario (fondamentale per inviare struct byte per byte senza conversioni di testo).
    // IMPORTANTE: Questa chiamata si BLOCCA finché il client dall'altra parte non apre in lettura!
    FILE* stream = fopen(fifo, "wb"); 
    
    // Se fopen restituisce NULL, qualcosa è andato storto (es. client sparito, permessi)
    if (!stream) { 
        perror(BOLD RED"[ERRORE] fopen send_response"RES); 
        return -1; 
    }

    // Scriviamo la struttura nel flusso.
    // &resp: indirizzo dei dati da scrivere.
    // sizeof(response_t): quanto è grande un pacchetto.
    // 1: quanti pacchetti scrivere.
    // stream: dove scriverli.
    // fwrite restituisce il numero di elementi scritti con successo (deve essere 1).
    int ret = (fwrite(&resp, sizeof(response_t), 1, stream) == 1) ? 0 : -1;
    
    // Se non ne ha scritto 1, stampiamo errore
    if (ret == -1) { 
        printf(BOLD RED"[ERRORE] Impossibile inviare la risposta a %s"RES"\n", fifo); 
    }
    
    // Chiudiamo il flusso. Questo invia fisicamente i dati rimanenti nel buffer e chiude il file.
    fclose(stream);
    
    // Ritorniamo 0 (successo) o -1 (errore)
    return ret;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: send_request
// Usata dal CLIENT per inviare una richiesta (request_t) al server.
// Funziona esattamente come send_response, ma invia una request_t.
// -------------------------------------------------------------------------------------
int send_request(const char* server_fifo, request_t req) {
    // Apre la FIFO del server in scrittura binaria
    FILE* stream = fopen(server_fifo, "wb");
    
    // Controllo errori apertura
    if (!stream) { 
        perror(BOLD RED"[ERRORE] fopen send_request"RES); 
        return -1; 
    }

    // Scrive la struttura request_t dentro la pipe
    int ret = (fwrite(&req, sizeof(request_t), 1, stream) == 1) ? 0 : -1;
    
    // Controllo errori scrittura
    if (ret == -1) { 
        printf(BOLD RED"[ERRORE] Impossibile inviare la richiesta a %s"RES"\n", server_fifo); 
    }
    
    // Chiude lo stream
    fclose(stream);
    return ret;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: read_response
// Usata dal CLIENT (nella modalità semplice, es. statistiche) per leggere la risposta.
// Nota: Non usiamo questa funzione per la lettura dell'hash nel client avanzato,
// perché lì usiamo il trucco del 'poll' e 'fdopen' direttamente nel client.c.
// -------------------------------------------------------------------------------------
int read_response(const char* fifo, response_t* resp) {
    // Apre la FIFO in modalità "Read Binary" ("rb").
    FILE* stream = fopen(fifo, "rb"); 
    
    if (!stream) { 
        perror(BOLD RED"[ERRORE] fopen read_response"RES); 
        return -1; 
    }
    
    // Legge 1 struttura response_t dallo stream e la mette all'indirizzo 'resp'.
    // fread restituisce il numero di elementi letti (deve essere 1).
    int ret = (fread(resp, sizeof(response_t), 1, stream) == 1) ? 0 : -1;
    
    if (ret == -1) { 
        printf(BOLD RED"[ERRORE] Lettura risposta fallita da %s"RES"\n", fifo); 
    }
    
    // Chiude lo stream
    fclose(stream);
    return ret;
}

// -------------------------------------------------------------------------------------
// FUNZIONE: elapsed_time
// Calcola la differenza in secondi (con la virgola) tra due tempi precisi.
// -------------------------------------------------------------------------------------
double elapsed_time(struct timespec start, struct timespec end) {
    // Le struct timespec hanno due campi: 
    // tv_sec: i secondi interi (es. 167888...)
    // tv_nsec: i nanosecondi rimanenti (0 a 999.999.999)
    
    // Formula: (Differenza secondi) + (Differenza nanosecondi diviso 1 miliardo)
    // 1e9 è la notazione scientifica per 1.000.000.000 (un miliardo).
    // Dividendo per 1e9 convertiamo i nanosecondi in secondi (es. 500ms diventa 0.5s).
    double result = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 ; 
    
    return result;
}