// --- GUARDIE DI INCLUSIONE ---
// Queste righe servono a evitare un errore classico: se per sbaglio includi questo file due volte
// (magari indirettamente), il compilatore andrebbe in confusione definendo le stesse cose due volte.
// #ifndef significa "If Not Defined" (Se non è già stato definito COMMON_H...)
#ifndef COMMON_H
// ...allora definiscilo adesso ed esegui tutto il codice qui sotto.
#define COMMON_H

// --- LIBRERIE CONDIVISE ---
// Includiamo qui le librerie standard che servono un po' ovunque, così non dobbiamo
// ripeterle in ogni singolo file .c.
#include <sys/types.h>  // Definisce tipi di sistema come 'pid_t' (ID del processo) o 'off_t' (dimensione file)
#include <time.h>       // Serve per le strutture 'timespec' (misurazione del tempo)
#include <stdbool.h>    // Ci permette di usare 'true' e 'false' invece di 1 e 0
#include <stdint.h>     // Definisce interi a grandezza fissa (es. uint64_t)
#include <stddef.h>     // Definisce 'size_t' e NULL

// --- COSTANTI DI CONFIGURAZIONE ---
// Il percorso fisso dove il Server ascolta le richieste. È come l'indirizzo dell'ufficio postale centrale.
#define REQ_FIFO_PATH "/tmp/hash_server"
// Il prefisso per le FIFO dei client. Verrà completato col PID (es. /tmp/hash_client_1234)
#define CLIENT_FIFO_PATH "/tmp/hash_client_"
// Lunghezza massima di un percorso file (1024 caratteri è standard in Linux)
#define PATH_MAX_LEN 1024
// Lunghezza della stringa dell'hash SHA256 (64 caratteri esadecimali)
#define HASH_LEN 64

// --- IL PROTOCOLLO (TIPI DI MESSAGGIO) ---
// Qui Client e Server si mettono d'accordo sul significato dei numeri.
// Invece di spedire "Voglio l'hash", spediscono il numero 0. È più efficiente.
#define HASH_A_FILE     0   // "Calcolami l'hash di questo file"
#define CLOSE_SERVER    1   // "Spegniti"
#define GET_STATISTICS  2   // "Dammi i numeri delle performance"
#define SEND_HASH       3   // "Ecco, tieni l'hash che hai chiesto"
#define SEND_ERROR      4   // "C'è stato un problema"
#define SEND_STATISTICS 5   // "Ecco le statistiche che hai chiesto"

// --- COLORI PER IL TERMINALE (ANSI ESCAPE CODES) ---
// Queste stringhe strane dicono al terminale "da qui in poi scrivi in Rosso/Verde/ecc".
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RES     "\x1b[0m" // RESET: Torna al colore normale
#define BOLD    "\x1b[1m" // GRASSETTO

// --- MACRO DI UTILITÀ (TRUCCHI DA PRO) ---
// Le macro sono dei "timbri". Prima di compilare, il preprocessore C sostituisce
// queste parole con il blocco di codice definito a destra.

// LOG_ERR: Stampa un errore standard in ROSSO su stderr.
// Usa '...' e __VA_ARGS__ per accettare un numero variabile di argomenti (come printf).
// Il "do { ... } while(0)" è un trucco tecnico per rendere la macro sicura dentro gli 'if'.
#define LOG_ERR(fmt, ...) do { \
    fprintf(stderr, BOLD RED "[ERRORE]" RES fmt "\n", ##__VA_ARGS__); \
} while(0);

// FATAL: Stampa l'errore e chiude brutalmente il programma (exit).
#define FATAL(fmt, ...) do { \
    LOG_ERR(fmt, ##__VA_ARGS__); \
    exit(EXIT_FAILURE); \
} while(0);

// EXIT_IF: Se la condizione (cond) è vera, stampa l'errore e muori.
// Esempio d'uso: EXIT_IF(n_threads < 0, "Numero thread invalido");
#define EXIT_IF(cond, fmt, ...) do { \
    if (cond) { FATAL(fmt, ##__VA_ARGS__); } \
} while(0);

// CHECK_ALLOC: Controlla se malloc/calloc hanno restituito NULL (memoria piena).
#define CHECK_ALLOC(ptr) do { \
    if ((ptr) == NULL) { \
        LOG_ERR(BOLD RED"[ERRORE] Allocazione della memoria fallita"); \
    } \
} while(0);

// CHECK: Esegue una funzione, se restituisce un errore (non 0), stampa il motivo (strerror).
// Utilissimo per le funzioni pthread_... che non settano errno ma ritornano il codice errore.
#define CHECK(func_call) do { \
    int _err = (int)(func_call); \
    if (_err != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #func_call, strerror(_err)); \
    }; \
} while(0);

// CHECK_RET: Simile a CHECK, ma se fallisce fa ritornare -1 alla funzione chiamante.
#define CHECK_RET(fcall) do { \
    int _error = (fcall); \
    if (_error != 0) { \
        fprintf(stderr, BOLD RED "[ERRORE] %s Fallita: %s\n" RES, #fcall, strerror(_error)); \
        return -1; \
    }; \
} while(0);

// --- STRUTTURE DATI (I MODULI DA COMPILARE) ---

// stats_t: Il foglio dove il server segna i suoi numeri.
typedef struct {
    unsigned long num_processed;      // Quanti file ha calcolato
    unsigned long num_requests;       // Quante richieste totali ha ricevuto
    double average_proc_time;         // Tempo medio (media mobile)
    unsigned long cache_hits;         // Quante volte ha trovato il file già pronto
    unsigned long cache_misses;       // Quante volte ha dovuto calcolarlo
} stats_t;

// request_t: La busta che il CLIENT spedisce al SERVER.
typedef struct {
    char path[PATH_MAX_LEN];          // Il file di cui vuole l'hash
    char response_fifo_path[PATH_MAX_LEN]; // "Rispondimi a questo indirizzo"
    pid_t pid;                        // "Sono il processo numero..."
    int type;                         // "Voglio un HASH (0) o le STATISTICHE (2)?"
} request_t;

// response_t: La busta che il SERVER spedisce al CLIENT.
typedef struct {
    char hash[HASH_LEN + 1];          // Il risultato (se c'è)
    char message[256];                // Messaggio (usato in caso di errore)
    int error_code;                   // Codice numerico dell'errore (errno)
    int type;                         // "Ti sto mandando un HASH (3) o un ERRORE (4)?"
    stats_t stats;                    // Se avevi chiesto statistiche, eccole qui.
} response_t;

// --- PROTOTIPI DI FUNZIONE ---

// Crea una FIFO in modo sicuro
int create_fifo(const char* path, mode_t mode);

// Spedisce un pacchetto di risposta (Server -> Client)
int send_response(const char* fifo, response_t response);

// Spedisce un pacchetto di richiesta (Client -> Server)
int send_request(const char* server_fifo, request_t request);

// Legge una risposta (Client <- Server)
int read_response(const char* fifo, response_t* response);

// Calcola la differenza di tempo in secondi con la virgola
double elapsed_time(struct timespec start, struct timespec end);

#endif // Chiude l'#ifndef iniziale