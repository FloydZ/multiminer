#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
//#include <time.h>
//#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>

#include "miner.h"
#include "equihash/cpu_simple/blake/blake2.h"
//#include "crypto/blake2b.h"


typedef struct element_indice element_indice_t;
typedef struct element element_t;
typedef struct bucket bucket_t;

void equihash_init_buckets(bucket_t **, bucket_t **,
                           element_indice_t *** indices);

size_t equihash(uint32_t dst_solutions[20][512], const blake2b_state *,
                bucket_t *, bucket_t *, element_indice_t ** indices);

void threaded_equihash(void *targ);

void create_header(blake2b_state * ctx, const char *header, size_t header_size, uint32_t nce);
//OLD void create_header(blake2b_state * ctx, const char *header, size_t header_size, const char* nce, const size_t nonceLen);

int scanhash_equihash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
