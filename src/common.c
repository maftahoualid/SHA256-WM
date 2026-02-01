#include "common.h"         // Include header condiviso con definizioni e prototipi
#include <stdio.h>          // Include libreria I/O standard (printf, perror)
#include <stdlib.h>         // Include libreria standard (exit, malloc)
#include <string.h>         // Include funzioni stringhe (strerror)
#include <unistd.h>         // Include primitive POSIX (read, write, close, unlink)
#include <fcntl.h>          // Include flag per open (O_RDONLY, O_WRONLY)
#include <errno.h>          // Include gestione codici errore (errno, EEXIST, EINTR)
#include <sys/stat.h>       // Include funzioni e macro per stat file (mkfifo, stat, S_ISFIFO)

int ensure_fifo(const char* path, mode_t mode) { // Crea una FIFO o verifica se esiste
    if (mkfifo(path, mode) == 0) return 0; // Tenta di creare la FIFO. Se 0, successo (creata nuova)
    if (errno != EEXIST) { perror("mkfifo"); return -1; } // Se errore diverso da "Esiste già", fallisce
    struct stat st; // Struttura per contenere info file
    // Controlla se il path esistente è davvero una FIFO
    if (stat(path, &st) == 0 && S_ISFIFO(st.st_mode)) { return 0; } // Se è una FIFO, tutto ok (riutilizziamo)
    fprintf(stderr, "Errore: '%s' esiste e non è una FIFO.\n", path); // Errore: esiste ma è un file/dir normale
    return -1; // Ritorna errore
}

int open_fifo_read(const char* path) { // Apre FIFO in lettura
    int fd = open(path, O_RDONLY); // System call open in sola lettura (Bloccante di default)
    if (fd == -1) { perror("open fifo read"); } // Se -1, stampa errore
    return fd; // Ritorna file descriptor
}

int open_fifo_write(const char* path) { // Apre FIFO in scrittura
    int fd = open(path, O_WRONLY); // System call open in sola scrittura (Bloccante se nessuno legge)
    if (fd == -1) { perror("open fifo write"); } // Se -1, stampa errore
    return fd; // Ritorna file descriptor
}

int send_response(const char* fifo, response_msg_t resp) { // Invia messaggio risposta a FIFO specifica
    int fd = open_fifo_write(fifo); // Apre la FIFO destinazione
    if (fd == -1) return -1; // Se apertura fallisce, ritorna errore
    // Scrive l'intera struttura. Se fallisce, stampa warning
    if (write_exact(fd, &resp, sizeof(resp)) == -1) { printf("Warning: Failed to send response to %s\n", fifo); } 
    close(fd); // Chiude subito il descrittore (comunicazione stateless per singola risposta)
    return fd; // Ritorna il (vecchio) fd o status (nota: fd è chiuso qui, ritorno poco utile se non per check > 0)
}

int send_request(const char* server_fifo, request_msg_t req) { // Invia richiesta al server
    int fd = open_fifo_write(server_fifo); // Apre FIFO server in scrittura
    if (fd == -1) return -1; // Errore apertura
    // Scrive l'intera struttura richiesta in modo atomico (se < PIPE_BUF)
    if (write_exact(fd, &req, sizeof(req)) == -1) { printf("Warning: Failed to send request to %s\n", server_fifo); }
    close(fd); // Chiude connessione
    return fd; // Ritorna status
}

int read_response(const char* fifo, response_msg_t* resp) { // Legge risposta da FIFO
    int fd = open_fifo_read(fifo); // Apre FIFO in lettura
    if (fd == -1) return -1; // Errore apertura
    
    if (read_exact(fd, resp, sizeof(*resp)) == -1) { // Tenta di leggere esattamente sizeof(response_msg_t) byte
        close(fd); // Se fallisce, chiude
        return -1; // Ritorna errore
    }
    
    close(fd); // Chiude dopo lettura completata
    return 0; // Successo
}

int read_exact(int fd, void* buf, size_t n) { // Helper per lettura robusta di N byte
    char* p = (char*)buf; // Casting a char* per aritmetica puntatori
    size_t remaining = n; // Byte rimanenti da leggere

    while (remaining > 0) { // Ciclo finché non abbiamo letto tutto
        ssize_t bytes_read = read(fd, p, remaining); // Legge fino a 'remaining' byte
        if (bytes_read <= 0) { // Se errore o EOF (0)
            if (bytes_read == -1 && errno == EINTR) { // Se interrotto da segnale (es. CTRL+Z/C gestito)
                continue; // Riprova la lettura (non è un vero errore)
            }
            return -1; // Errore reale o EOF inatteso (pacchetto incompleto)
        }
        p += bytes_read; // Avanza il puntatore nel buffer
        remaining -= bytes_read; // Decrementa il contatore byte mancanti
    }
    return 0; // Tutto letto correttamente
}

int write_exact(int fd, const void* buf, size_t n) { // Helper per scrittura robusta di N byte
    const char* p = (const char*)buf; // Casting per aritmetica
    size_t remaining = n; // Byte rimanenti da scrivere

    while (remaining > 0) { // Ciclo scrittura
        ssize_t bytes_written = write(fd, p, remaining); // Scrive
        if (bytes_written <= 0) { // Se errore
            if (bytes_written == -1 && errno == EINTR) { // Se interrotto da segnale
                continue; // Riprova
            }
            return -1; // Errore reale (es. pipe rotta, disco pieno)
        }
        p += bytes_written; // Avanza cursore
        remaining -= bytes_written; // Decrementa rimanenti
    }
    return 0; // Tutto scritto
}

double get_time_diff(struct timespec start, struct timespec end) { // Calcola differenza tempo in secondi (double)
    // Formula: (diff_secondi) + (diff_nanosecondi / 1 miliardo)
    double result = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9 ; 
    return result; // Ritorna tempo trascorso
}

void print_usage(const char* progname) { // Stampa istruzioni uso CLI
    printf("Usage: %s [OPTIONS]\n", progname); // Intestazione
    printf("Options:\n"); // Sezione opzioni
    printf("  -h, --help              Show this help message\n"); // Help
    printf("  -w, --workers N         Number of worker threads (default: 4)\n"); // Opzione workers
    printf("  -o, --order asc|desc    File processing order (default: asc)\n"); // Opzione ordine
    printf("  -s, --stats             Show server statistics\n"); // Opzione stats
    printf("  -t, --terminate         Terminate server\n"); // Opzione terminate
    printf("  FILE                    Request hash for FILE\n"); // Argomento file posizionale
}