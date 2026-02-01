#ifndef COMMON_H // Guardie di inclusione: inizia il blocco se COMMON_H non è definito
#define COMMON_H // Definisce COMMON_H per evitare inclusioni multiple dello stesso header

#include <sys/types.h> // Include definizioni di tipi di sistema come pid_t, off_t
#include <time.h>      // Include strutture per il tempo (struct timespec)
#include <stdbool.h>   // Include il tipo booleano (true/false)
#include <stddef.h>    // Include definizioni standard come size_t, NULL

#define REQUEST_FIFO_PATH "/tmp/sha256_req_fifo" // Percorso della FIFO pubblica dove il server ascolta le richieste
#define CLIENT_FIFO_PREFIX "/tmp/sha256_resp_"   // Prefisso per le FIFO private di risposta dei client (verrà aggiunto il PID)
#define MAX_PATH_LEN 1024 // Lunghezza massima supportata per i percorsi dei file (buffer statici)
#define HASH_HEX_LEN 64   // Lunghezza della stringa hash SHA256 in esadecimale (32 byte * 2 char)

#define REQ_HASH_FILE 0 // Codice op: Richiesta di calcolo hash di un file
#define REQ_TERMINATE 1 // Codice op: Richiesta di terminazione del server
#define REQ_STATS     2 // Codice op: Richiesta delle statistiche del server
#define RESP_HASH     3 // Codice op: Risposta contenente l'hash calcolato
#define RESP_ERROR    4 // Codice op: Risposta indicante un errore
#define RESP_STATS    5 // Codice op: Risposta contenente le statistiche

typedef struct { // Definizione struttura del messaggio di richiesta (Client -> Server)
    int type; // Tipo di richiesta (vedi define REQ_*)
    char path[MAX_PATH_LEN]; // Percorso del file da processare (o vuoto per stats/term)
    char resp_fifo[MAX_PATH_LEN]; // Percorso della FIFO dove il client aspetta la risposta
    pid_t client_pid; // PID del processo client (utile per debug o log server)
} request_msg_t; // Nome del tipo struttura richiesta

typedef struct { // Definizione struttura del messaggio di risposta (Server -> Client)
    int type; // Tipo di risposta (vedi define RESP_*)
    char hash[HASH_HEX_LEN + 1]; // Buffer per la stringa hash (+1 per terminatore null)
    char error_msg[256]; // Buffer per eventuale messaggio di errore o stringa statistiche
    int error_code; // Codice numerico dell'errore (es. errno)
} response_msg_t; // Nome del tipo struttura risposta

// Prototipi delle funzioni definite in common.c:

int ensure_fifo(const char* path, mode_t mode); // Crea FIFO o verifica esistenza
int open_fifo_read(const char* path); // Apre FIFO in sola lettura
int open_fifo_write(const char* path); // Apre FIFO in sola scrittura
int send_response(const char* fifo, response_msg_t resp); // Invia risposta su FIFO specifica
int send_request(const char* server_fifo, request_msg_t req); // Invia richiesta alla FIFO server
int read_response(const char* fifo, response_msg_t* resp); // Legge risposta da FIFO
int read_exact(int fd, void* buf, size_t n); // Helper per leggere esattamente n byte
int write_exact(int fd, const void* buf, size_t n); // Helper per scrivere esattamente n byte
double get_time_diff(struct timespec start, struct timespec end); // Calcola delta tempo in secondi
void print_usage(const char* progname); // Stampa help utilizzo CLI

#endif // Fine della guardia di inclusione