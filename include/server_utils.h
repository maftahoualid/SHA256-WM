#ifndef SERVER_UTILS_H
#define SERVER_UTILS_H

#include "server_structs.h"

extern server_t* g_server;

int compute_sha256(const char* filepath, char* hash_hex);

void close_queue(job_queue_t* queue);

void add_to_queue(job_queue_t* queue, const char* path, const char* response_fifo_path, pid_t pid, off_t size);

int get_from_queue(job_queue_t* queue, job_t* j);

void close_cache(cache_t* cache);

cache_entry_t* get_cache_entry(cache_t* cache, const char* path);

bool search_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, char* hash_out);

void add_to_cache(cache_t* cache, const char* path, off_t size, time_t last_upd_sec, long last_upd_nsec, const char* hash);

void signal_handler(int sig);

void* thread_function(void* arg);

int init_server(server_t* ctx, int num_workers, int order);

void close_server(server_t* ctx);

int run_server(server_t* ctx);

void show_statistics(const stats_t* stats);

#endif