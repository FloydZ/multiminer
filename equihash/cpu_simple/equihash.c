#define _XOPEN_SOURCE 700
#define _BSD_SOURCE //für hton

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <endian.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <endian.h>
#include <assert.h>

#include "equihash/cpu_simple/equihash.h"
#include "equihash/cpu_simple/blake/blake2.h"

//#include "crypto/blake2b.h"
/*
    gcc-5 equihash-time.c thpool/thpool.c equihash-opt.c --pedantic -Wall -std=c11 -o time-equihash -lsodium -lpthread -ffast-math -pthread -D_POSIX_SOURCE -ggdb -pg -Ofast -march=native
*/

#define EQUIHASH_N 200
#define EQUIHASH_K 9

#define NUM_COLLISION_BITS (EQUIHASH_N / (EQUIHASH_K + 1))
#define NUM_INDICES (1 << EQUIHASH_K)

#define NUM_VALUES (1 << (NUM_COLLISION_BITS+1))
#define NUM_ELEMENTS_BYTES_PER_BUCKET (1 << 9)
#define NUM_BUCKETS (1 << NUM_COLLISION_BITS)/NUM_ELEMENTS_BYTES_PER_BUCKET
#define DIGEST_SIZE 32


//NEW
#define NDIGITS  (EQUIHASH_K+1)
#define DIGITBITS (EQUIHASH_N/(NDIGITS))
#define PROOFSIZE (1<<EQUIHASH_K)
#define BASE (1<<DIGITBITS)
#define NHASHES (2*BASE)
#define HASHESPERBLAKE (512/EQUIHASH_N)
#define HASHOUT (HASHESPERBLAKE*EQUIHASH_N/8)


typedef struct element_indice {
  uint32_t a;
  uint32_t b;
} element_indice_t;

typedef struct element {
  uint64_t digest[3];
  uint32_t a;
  uint32_t b;
} element_t;

typedef struct bucket {
  uint64_t size;
  element_t data[NUM_ELEMENTS_BYTES_PER_BUCKET * 3];
} bucket_t;

uint32_t mask_collision_bits(uint8_t * data, size_t start)
{
  size_t byte_index = start / 8;
  size_t bit_index = start % 8;
  uint32_t n = ((data[byte_index] << (bit_index)) & 0xff) << 12;
  n |= ((data[byte_index + 1]) << (bit_index + 4));
  n |= ((data[byte_index + 2]) >> (4 - bit_index));
  return n;
}

uint32_t mask_collision_byte_bits_even(uint8_t * data)
{
  return (data[0] << 12) | (data[1] << 4) | (data[2] >> 4);
}

uint32_t mask_collision_byte_bits_odd(uint8_t * data)
{
  return (((data[0] << 4) & 0xff) << 12) | (data[1] << 8) | (data[2]);
}

uint32_t mask_collision_byte_bits_even_sub_bucket(uint8_t * data)
{
  return (data[1] << 4) | (data[2] >> 4);
}


uint32_t mask_collision_byte_bits_odd_sub_bucket(uint8_t * data)
{
  return (data[1] << 8) | (data[2]);
}



uint32_t
mask_collision_byte_bits(uint8_t * data, size_t byte_index, size_t bit_index)
{
  return (((data[byte_index] << (bit_index)) & 0xff) << 12)
    | ((data[byte_index + 1]) << (bit_index + 4))
    | ((data[byte_index + 2]) >> (4 - bit_index));
}

uint32_t
mask_collision_byte_bits_final(uint8_t * data, size_t byte_index,
                               size_t bit_index)
{
  return (((data[byte_index] << (bit_index)) & 0xff) << 12)
    | ((data[byte_index + 1]) << (bit_index + 4));
}


int compare_indices32(uint32_t * a, uint32_t * b, size_t n_current_indices)
{
  for (size_t i = 0; i < n_current_indices; ++i, ++a, ++b) {
    if (*a < *b) {
      return -1;
    } else if (*a > *b) {
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}

void normalize_indices(uint32_t * indices)
{
  for (size_t step_index = 0; step_index < EQUIHASH_K; ++step_index) {
    for (size_t i = 0; i < NUM_INDICES; i += (1 << (step_index + 1))) {
      if (compare_indices32
          (indices + i, indices + i + (1 << step_index),
           (1 << step_index)) > 0) {
        uint32_t tmp_indices[(1 << step_index)];
        memcpy(tmp_indices, indices + i, (1 << step_index) * sizeof(uint32_t));
        memcpy(indices + i, indices + i + (1 << step_index),
               (1 << step_index) * sizeof(uint32_t));
        memcpy(indices + i + (1 << step_index), tmp_indices,
               (1 << step_index) * sizeof(uint32_t));
      }
    }
  }
}


void xor_elements(uint64_t * dst, uint64_t * a, uint64_t * b)
{
  dst[0] = a[0] ^ b[0];
  dst[1] = a[1] ^ b[1];
  dst[2] = a[2] ^ b[2];
}

void xor_elements_4_7(uint64_t * dst, uint64_t * a, uint64_t * b)
{
  dst[1] = a[1] ^ b[1];
  dst[2] = a[2] ^ b[2];
}

void xor_elements_8(uint64_t * dst, uint64_t * a, uint64_t * b)
{
  dst[2] = a[2] ^ b[2];
}


void hash(uint8_t * dst, uint32_t in, const blake2b_state * digest)
{
  uint32_t tmp_in = in / 2;
  blake2b_state new_digest = *digest;//OWN
  _blake2b_update(&new_digest, (uint8_t *) & tmp_in, sizeof(uint32_t));
  _blake2b_final(&new_digest, (uint8_t *) dst, 2 * DIGEST_SIZE);
}


uint32_t
decompress_indices(uint32_t * dst_uncompressed_indices,
                   element_indice_t ** indices, uint32_t a, uint32_t b)
{
  element_indice_t elements[EQUIHASH_K][NUM_INDICES];
  elements[0][0].a = a;
  elements[0][0].b = b;

  for (size_t i = 0; i < EQUIHASH_K - 1; ++i) {
    for (size_t j = 0; j < (1 << i); ++j) {
      element_indice_t *src = elements[i] + j;
      elements[i + 1][2 * j] = indices[EQUIHASH_K - 2 - i][src->a];
      elements[i + 1][2 * j + 1] = indices[EQUIHASH_K - 2 - i][src->b];
    }
  }

  uint32_t last_collision = 0;
  for (size_t j = 0; j < NUM_INDICES / 2; ++j) {
    element_indice_t *src = elements[EQUIHASH_K - 1] + j;
    *dst_uncompressed_indices = src->a;
    last_collision ^= src->b;
    dst_uncompressed_indices++;
  }
  return last_collision;
}

void initial_bucket_hashing(bucket_t * dst, const blake2b_state * digest)
{
  size_t last_bit = ((EQUIHASH_K) * NUM_COLLISION_BITS);
  size_t last_byte = last_bit / 8;
  size_t last_rel_bit = last_bit % 8;

  double t = get_tttime();
  uint8_t new_digest[2 * DIGEST_SIZE];
  memset(new_digest, '\0', 2 * DIGEST_SIZE);
  element_t *tmp_dst_buckets[NUM_BUCKETS];
  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    tmp_dst_buckets[i] = (dst + i)->data;
  }



  for (uint32_t i = 0, c = 0; i < NUM_VALUES / 2; ++i, c += 2) {
    blake2b_state current_digest = *digest;
    _blake2b_update(&current_digest, (uint8_t *) & i, sizeof(uint32_t));
    _blake2b_final(&current_digest, (uint8_t *) (new_digest), 50);

    {
      uint32_t new_index =
        mask_collision_byte_bits_even(new_digest +
                                      0) / NUM_ELEMENTS_BYTES_PER_BUCKET;
      element_t *new_el = tmp_dst_buckets[new_index]++;
      new_el->a = c;
      new_el->b = mask_collision_byte_bits(new_digest, last_byte, last_rel_bit);
      memcpy(new_el->digest, new_digest, 24);
    }

    {
      uint32_t new_index =
        mask_collision_byte_bits_even(new_digest + 25 +
                                      0) / NUM_ELEMENTS_BYTES_PER_BUCKET;
      element_t *new_el = tmp_dst_buckets[new_index]++;
      new_el->a = c + 1;
      new_el->b =
        mask_collision_byte_bits(new_digest + 25, last_byte, last_rel_bit);
      memcpy(new_el->digest, new_digest + 25, 24);
    }
  }
  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    dst[i].size =
      ((uintptr_t) tmp_dst_buckets[i] -
       (uintptr_t) dst[i].data) / sizeof(element_t);
  }
  printf("init: (%f)\n", get_tttime() - t);
}

void
collide_1_3(bucket_t * dst, bucket_t * src, element_indice_t * old_indices,
            size_t step_index)
{
  size_t start_bit = ((step_index - 1) * NUM_COLLISION_BITS);
  size_t start_byte = start_bit / 8;

  size_t last_bit = (step_index * NUM_COLLISION_BITS);
  size_t last_byte = last_bit / 8;

  size_t indice_index = 0;
  //double //tsort = 0;
  //double //tcollide = 0;
  double t3 = get_tttime();


  element_t *tmp_dst_buckets[NUM_BUCKETS];
  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    tmp_dst_buckets[i] = (dst + i)->data;
  }


  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    bucket_t *bucket = src + i;
    //double t1 = get_tttime();
    uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
    uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
    memset(sub_bucket_sizes, '\0',
           NUM_ELEMENTS_BYTES_PER_BUCKET * sizeof(uint32_t));
    element_t *bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + start_byte);
    element_t *next_bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + last_byte);


    if (step_index % 2 == 1) {
      for (uint32_t j = 0; j < bucket->size; ++j) {
        uint32_t sub_index =
          mask_collision_byte_bits_even_sub_bucket((uint8_t *)
                                                   bucket_data) %
          NUM_ELEMENTS_BYTES_PER_BUCKET;
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
          mask_collision_byte_bits_odd((uint8_t *) next_bucket_data);
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
        bucket_data++;
        next_bucket_data++;
        sub_bucket_sizes[sub_index]++;
      }
    } else {
      for (uint32_t j = 0; j < bucket->size; ++j) {
        uint32_t sub_index =
          mask_collision_byte_bits_odd((uint8_t *) bucket_data) %
          NUM_ELEMENTS_BYTES_PER_BUCKET;
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
          mask_collision_byte_bits_even((uint8_t *) next_bucket_data);
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
        bucket_data++;
        next_bucket_data++;
        sub_bucket_sizes[sub_index]++;
      }
    }

    //double t2 = get_tttime();
    ////////printf("%u bucket->size: %u\n", step_index, bucket->size);
    //tsort += t2 - t1;
    for (uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
      uint32_t sub_bucket_size = sub_bucket_sizes[o] * 2;
      ////////printf("size: %u - %u\n", bucket->size, sub_bucket_size);

      if (sub_bucket_size <= 2) {
        continue;
      }

      uint32_t *sub_bucket_indices = (uint32_t *) sub_buckets[o];
      for (uint32_t j = 0; j < sub_bucket_size; j += 2) {
        uint32_t base_bits = sub_bucket_indices[j + 0]; //mask_collision_bits(base->digest, last_bit);
        element_t *base = bucket->data + sub_bucket_indices[j + 1];
        old_indices->a = base->a;
        old_indices->b = base->b;

        for (uint32_t k = j + 2; k < sub_bucket_size; k += 2) {
          uint32_t new_index = base_bits ^ sub_bucket_indices[k + 0];   //mask_collision_bits(el->digest, last_bit);
          if (__builtin_expect(new_index == 0, 0))
            continue;

          element_t *new_el =
            tmp_dst_buckets[new_index / NUM_ELEMENTS_BYTES_PER_BUCKET]++;
          xor_elements(new_el->digest, base->digest,
                       (bucket->data + sub_bucket_indices[k + 1])->digest);
          new_el->a = indice_index;
          new_el->b = indice_index + (k - j) / 2;
        }
        indice_index++;
        old_indices++;
      }
    }
    //return;
    //tcollide += (get_tttime()-t2);
  }
  //printf("here2\n");

  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    src[i].size = 0;
    dst[i].size = ((uintptr_t) tmp_dst_buckets[i] - (uintptr_t) dst[i].data) / sizeof(element_t);       //tmp_dst_bucket_sizes[i];
  }

  double ttot = get_tttime() - t3;
  printf("colliding %zu: %zu (%f)\n", step_index, indice_index, ttot);
}


// idea: copy in segments of 2 at first then the rest
void
collide_4_7(bucket_t * dst, bucket_t * src, element_indice_t * old_indices,
            size_t step_index)
{
  size_t start_bit = ((step_index - 1) * NUM_COLLISION_BITS);
  size_t start_byte = start_bit / 8;

  size_t last_bit = ((step_index) * NUM_COLLISION_BITS);
  size_t last_byte = last_bit / 8;

  size_t indice_index = 0;
  double tsort = 0;
  double tcollide = 0;
  double t3 = get_tttime();


  element_t *tmp_dst_buckets[NUM_BUCKETS];
  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    tmp_dst_buckets[i] = (dst + i)->data;
  }


  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    bucket_t *bucket = src + i;
    double t1 = get_tttime();
    uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
    uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
    memset(sub_bucket_sizes, '\0',
           NUM_ELEMENTS_BYTES_PER_BUCKET * sizeof(uint32_t));
    element_t *bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + start_byte);
    element_t *next_bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + last_byte);


    if (step_index % 2 == 1) {
      for (uint32_t j = 0; j < bucket->size; ++j) {
        uint32_t sub_index =
          mask_collision_byte_bits_even_sub_bucket((uint8_t *)
                                                   bucket_data) %
          NUM_ELEMENTS_BYTES_PER_BUCKET;
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
          mask_collision_byte_bits_odd((uint8_t *) next_bucket_data);
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
        bucket_data++;
        next_bucket_data++;
        sub_bucket_sizes[sub_index]++;
      }
    } else {
      for (uint32_t j = 0; j < bucket->size; ++j) {
        uint32_t sub_index =
          mask_collision_byte_bits_odd((uint8_t *) bucket_data) %
          NUM_ELEMENTS_BYTES_PER_BUCKET;
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
          mask_collision_byte_bits_even((uint8_t *) next_bucket_data);
        sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
        bucket_data++;
        next_bucket_data++;
        sub_bucket_sizes[sub_index]++;
      }
    }

    double t2 = get_tttime();
    //////printf("%u bucket->size: %u\n", step_index, bucket->size);
    tsort += t2 - t1;
    for (uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
      uint32_t sub_bucket_size = sub_bucket_sizes[o] * 2;
      if (sub_bucket_size <= 2) {
        continue;
      }

      uint32_t *sub_bucket_indices = (uint32_t *) sub_buckets[o];
      for (uint32_t j = 0; j < sub_bucket_size; j += 2) {
        uint32_t base_bits = sub_bucket_indices[j];     //mask_collision_bits(base->digest, last_bit);
        element_t *base = bucket->data + sub_bucket_indices[j + 1];
        old_indices->a = base->a;
        old_indices->b = base->b;

        for (uint32_t k = j + 2; k < sub_bucket_size; k += 2) {
          uint32_t new_index = base_bits ^ sub_bucket_indices[k];       //mask_collision_bits(el->digest, last_bit);
          if (__builtin_expect(new_index == 0, 0))
            continue;

          element_t *new_el =
            tmp_dst_buckets[new_index / NUM_ELEMENTS_BYTES_PER_BUCKET]++;
          xor_elements_4_7(new_el->digest, base->digest,
                           (bucket->data + sub_bucket_indices[k + 1])->digest);
          new_el->a = indice_index;
          new_el->b = indice_index + (k - j) / 2;
        }
        indice_index++;
        old_indices++;
      }
    }
    //return;
    tcollide += (get_tttime() - t2);
  }
  //printf("here2\n");

  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    src[i].size = 0;
    dst[i].size = ((uintptr_t) tmp_dst_buckets[i] - (uintptr_t) dst[i].data) / sizeof(element_t);       //tmp_dst_bucket_sizes[i];
  }

  double ttot = get_tttime() - t3;
  printf("colliding %zu: %zu (%f %f %f)\n", step_index,
          indice_index, tsort, tcollide, ttot);
}

// idea: copy in segments of 2 at first then the rest
void
collide_8(bucket_t * dst, bucket_t * src, element_indice_t * old_indices,
          size_t step_index)
{
  size_t start_bit = ((step_index - 1) * NUM_COLLISION_BITS);
  size_t start_byte = start_bit / 8;

  size_t last_bit = ((step_index) * NUM_COLLISION_BITS);
  size_t last_byte = last_bit / 8;

  size_t indice_index = 0;
  //double //tsort = 0;
  //double //tcollide = 0;
  double t3 = get_tttime();


  element_t *tmp_dst_buckets[NUM_BUCKETS];
  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    tmp_dst_buckets[i] = (dst + i)->data;
  }


  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    bucket_t *bucket = src + i;
    //double t1 = get_tttime();
    uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
    uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
    memset(sub_bucket_sizes, '\0',
           NUM_ELEMENTS_BYTES_PER_BUCKET * sizeof(uint32_t));
    element_t *bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + start_byte);
    element_t *next_bucket_data =
      (element_t *) (((uint8_t *) bucket->data) + last_byte);

    for (uint32_t j = 0; j < bucket->size; ++j) {
      uint32_t sub_index =
        mask_collision_byte_bits_odd_sub_bucket((uint8_t *) bucket_data)
        % NUM_ELEMENTS_BYTES_PER_BUCKET;
      sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
        mask_collision_byte_bits_even((uint8_t *) next_bucket_data);
      sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
      bucket_data++;
      next_bucket_data++;
      sub_bucket_sizes[sub_index]++;
    }

    //double t2 = get_tttime();
    ////////printf("%u bucket->size: %u\n", step_index, bucket->size);
    //tsort += t2 - t1;
    for (uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
      uint32_t sub_bucket_size = sub_bucket_sizes[o] * 2;
      if (sub_bucket_size <= 2) {
        continue;
      }

      uint32_t *sub_bucket_indices = (uint32_t *) sub_buckets[o];
      for (uint32_t j = 0; j < sub_bucket_size; j += 2) {
        uint32_t base_bits = sub_bucket_indices[j];     //mask_collision_bits(base->digest, last_bit);
        element_t *base = bucket->data + sub_bucket_indices[j + 1];
        old_indices->a = base->a;
        old_indices->b = base->b;

        for (uint32_t k = j + 2; k < sub_bucket_size; k += 2) {
          uint32_t new_index = base_bits ^ sub_bucket_indices[k];       //mask_collision_bits(el->digest, last_bit);
          if (__builtin_expect(new_index == 0, 0))
            continue;

          element_t *new_el =
            tmp_dst_buckets[new_index / NUM_ELEMENTS_BYTES_PER_BUCKET]++;
          xor_elements_8(new_el->digest, base->digest,
                         (bucket->data + sub_bucket_indices[k + 1])->digest);
          new_el->a = indice_index;
          new_el->b = indice_index + (k - j) / 2;
        }
        indice_index++;
        old_indices++;
      }
    }
    //tcollide += (get_tttime()-t2);
  }
  //printf("here2\n");

  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    src[i].size = 0;
    dst[i].size = ((uintptr_t) tmp_dst_buckets[i] - (uintptr_t) dst[i].data) / sizeof(element_t);       //tmp_dst_bucket_sizes[i];
  }

  double ttot = get_tttime() - t3;
  printf("colliding 8: %zu (%f)\n", indice_index, ttot);
}


size_t
produce_solutions(uint32_t * dst_solutions, bucket_t * src,
                  element_indice_t ** indices, size_t n_src_elements,
                  const blake2b_state * digest)
{
  size_t n_solutions = 0;
  size_t start_bit = ((EQUIHASH_K - 1) * NUM_COLLISION_BITS);
  size_t start_byte = start_bit / 8;
  size_t start_rel_bit = start_bit % 8;

  size_t last_bit = ((EQUIHASH_K) * NUM_COLLISION_BITS);
  size_t last_byte = last_bit / 8;
  size_t last_rel_bit = last_bit % 8;

  //double //tsort = 0;
  //double //tcollide = 0;
  double t3 = get_tttime();

  uint8_t dupes[1 << NUM_COLLISION_BITS];
  memset(dupes, '\0', 1 << NUM_COLLISION_BITS);


  for (uint32_t i = 0; i < NUM_BUCKETS; ++i) {
    bucket_t *bucket = src + i;
    //double t1 = get_tttime();
    uint32_t sub_bucket_sizes[NUM_ELEMENTS_BYTES_PER_BUCKET];
    uint32_t sub_buckets[NUM_ELEMENTS_BYTES_PER_BUCKET][17][2];
    memset(sub_bucket_sizes, '\0',
           NUM_ELEMENTS_BYTES_PER_BUCKET * sizeof(uint32_t));
    element_t *bucket_data = bucket->data;
    for (uint16_t j = 0; j < bucket->size; ++j) {
      uint32_t sub_index =
        mask_collision_byte_bits((uint8_t *) bucket_data->digest,
                                 start_byte,
                                 start_rel_bit) % NUM_ELEMENTS_BYTES_PER_BUCKET;
      sub_buckets[sub_index][sub_bucket_sizes[sub_index]][0] =
        mask_collision_byte_bits_final((uint8_t *) bucket_data->digest,
                                       last_byte, last_rel_bit);
      sub_buckets[sub_index][sub_bucket_sizes[sub_index]][1] = j;
      bucket_data++;
      sub_bucket_sizes[sub_index]++;
    }

    //double t2 = get_tttime();
    //tsort += t2 - t1;
    for (uint32_t o = 0; o < NUM_ELEMENTS_BYTES_PER_BUCKET; ++o) {
      uint32_t sub_bucket_size = sub_bucket_sizes[o] * 2;
      if (sub_bucket_size <= 2) {
        continue;
      }

      uint32_t *sub_bucket_indices = (uint32_t *) sub_buckets[o];

      int has_dupe = 0;
      for (uint32_t j = 0; j < sub_bucket_size && !has_dupe; j += 2) {
        uint32_t a1 = sub_bucket_indices[j];    //mask_collision_bits(base->digest, last_bit);

        for (uint32_t k = j + 2; k < sub_bucket_size; k += 2) {

          if (__builtin_expect(a1 == sub_bucket_indices[k] && a1 != 0, 0)) {
            uint32_t uncompressed_indices[NUM_INDICES];
            memset(uncompressed_indices, '\0', NUM_INDICES*sizeof(uint32_t));
            element_t *base = bucket->data + sub_bucket_indices[j + 1];
            element_t *el = bucket->data + sub_bucket_indices[k + 1];
            uint32_t last_collision = decompress_indices(uncompressed_indices, indices, base->a, base->b);
            last_collision ^= decompress_indices(uncompressed_indices + NUM_INDICES / 2, indices, el->a, el->b);

            if (__builtin_expect(last_collision != 0, 1)) {
              continue;
            }


            for (size_t d = 0; d < NUM_INDICES && !has_dupe; ++d) {
              for (size_t o = d + 1; o < NUM_INDICES && !has_dupe; ++o) {
                if (uncompressed_indices[d] == uncompressed_indices[o]) {
                  has_dupe = 1;
                }
              }
            }

            if (__builtin_expect(has_dupe, 1)) {
              break;
            }

            normalize_indices(uncompressed_indices);

            memcpy(dst_solutions + n_solutions * NUM_INDICES, uncompressed_indices, NUM_INDICES * sizeof(uint32_t));
            n_solutions++;
          }
        }
      }
    }
    bucket->size = 0;
    //tcollide += get_tttime() - t2;
  }
  double ttot = get_tttime() - t3;
  printf("%zu solutions (%f)\n", n_solutions, ttot);
  return n_solutions;
}

void
equihash_init_buckets(bucket_t ** src, bucket_t ** dst,
                      element_indice_t *** indices)
{
  (*indices) = (element_indice_t **) calloc(EQUIHASH_K - 1, sizeof(element_indice_t *));
  for (size_t i = 0; i < EQUIHASH_K - 1; ++i) {
    (*indices)[i] =
      (element_indice_t *) calloc(NUM_VALUES + (NUM_VALUES >> 2),
                                  sizeof(element_indice_t));
  }
  (*src) = (bucket_t *) calloc(NUM_BUCKETS, sizeof(bucket_t));
  (*dst) = (bucket_t *) calloc(NUM_BUCKETS, sizeof(bucket_t));
}

void
equihash_cleanup_buckets(bucket_t * src, bucket_t * dst,
                         element_indice_t ** indices)
{
  for (size_t i = 0; i < EQUIHASH_K - 1; ++i) {
    free(indices[i]);
  }
  free(indices);
  free(src);
  free(dst);
}

/*
size_t
equihash(uint32_t * dst_solutions, const blake2b_state * digest,
         bucket_t * src, bucket_t * dst, element_indice_t ** indices)
*/

size_t equihash(uint32_t dst_solutions[20][512], const blake2b_state *digest,
             bucket_t *src, bucket_t *dst, element_indice_t ** indices)
{
  //double t = get_tttime();
  initial_bucket_hashing(src, digest);
  ////////printf("init: %f\n", get_tttime() - t);
  size_t n_current_values = NUM_VALUES;

  for (size_t i = 1; i < 4; ++i) {
    collide_1_3(dst, src, indices[i - 1], i);
    bucket_t *tmp = src;
    src = dst;
    dst = tmp;
  }

  for (size_t i = 4; i < 8; ++i) {
    collide_4_7(dst, src, indices[i - 1], i);
    bucket_t *tmp = src;
    src = dst;
    dst = tmp;
  }

  for (size_t i = 8; i < 9; ++i) {
    collide_8(dst, src, indices[i - 1], i);
    bucket_t *tmp = src;
    src = dst;
    dst = tmp;
  }

  size_t n_solutions =
    produce_solutions(dst_solutions, src, indices, n_current_values, digest);
  ////////printf("final: %f\n", get_tttime() - t);
  return n_solutions;
}


//OWN
typedef struct equihash_thread_arg {
  blake2b_state state;
  bucket_t *src;
  bucket_t *dst;
  element_indice_t **indices;
} equihash_thread_arg_t;

static size_t n_solutions = 0;
static double start_time = 0;
static double min_time = 0xfffffff;
static double max_time = 0;

//Currently unused
void threaded_equihash(void *targ)
{
  uint32_t solutions[20][512];
  equihash_thread_arg_t *arg = targ;
  //double st = get_time();
  size_t tmp = equihash(solutions, &arg->state, arg->src, arg->dst, arg->indices);
  //double t = get_time() - st;
  //pthread_mutex_lock(&mutex);
  //printf("!!!num solutions: %u\n", tmp);
  //min_time = t < min_time ? t : min_time;
  //max_time = t > max_time ? t : max_time;
  n_solutions += tmp;
  //pthread_mutex_unlock(&mutex);
}

//void create_header(blake2b_state * ctx, const char *header, size_t header_size, const char* nce, const size_t nonceLen)
void create_header(blake2b_state *ctx, const char *header, const uint32_t header_size, uint32_t nce)
{
  uint32_t le_N = 200;
  uint32_t le_K = 9;
  uint8_t personal[] = "ZcashPoW01230123";
  memcpy(personal + 8, &le_N, 4);
  memcpy(personal + 12, &le_K, 4);
  blake2b_param P[1];
  P->digest_length = (512 / 200) * 200 / 8;
  P->key_length = 0;
  P->fanout = 1;
  P->depth = 1;
  P->leaf_length = 0;
  P->node_offset = 0;
  P->node_depth = 0;
  P->inner_length = 0;
  memset(P->reserved, 0, sizeof(P->reserved));
  memset(P->salt, 0, sizeof(P->salt));
  memcpy(P->personal, (const uint8_t *) personal, 16);
  _blake2b_init_param(ctx, P);
  _blake2b_update(ctx, (const uint8_t *) header, header_size);

  uint8_t nonce[32]; //TODO free
  memset(nonce, 0, 32);
  uint32_t le_nonce = nce;
  memcpy(nonce, &le_nonce, 4);
  _blake2b_update(ctx, nonce, 32);

  //OLD_blake2b_update(ctx, nce, nonceLen);

}

void genhash(blake2b_state *ctx, uint32_t idx, unsigned char *hash) {
    blake2b_state state = *ctx;
    uint32_t leb = htole32(idx / HASHESPERBLAKE);
    _blake2b_update(&state, (unsigned char *) & leb, sizeof (uint32_t));
    unsigned char blakehash[HASHOUT];
    _blake2b_final(&state, blakehash, HASHOUT);
    memcpy(hash, blakehash + (idx % HASHESPERBLAKE) * EQUIHASH_N / 8, EQUIHASH_N / 8);
}

//Ich glaube diese func programmieren
int verifyrec(blake2b_state *ctx, uint32_t *indices, unsigned char *hash, int r) {
    if (r == 0) {
        genhash(ctx, *indices, hash);
        return 0;//POW_OK;
    }
    uint32_t *indices1 = indices + (1 << (r - 1));
    if (*indices >= *indices1)
        return 2;//POW_OUT_OF_ORDER;
    unsigned char hash0[EQUIHASH_N / 8], hash1[EQUIHASH_N / 8];
    int vrf0 = verifyrec(ctx, indices, hash0, r - 1);
    if (vrf0 != 0/*POW_OK*/)
        return vrf0;
    int vrf1 = verifyrec(ctx, indices1, hash1, r - 1);
    if (vrf1 != 0/*POW_OK*/)
        return vrf1;
    for (int i = 0; i < EQUIHASH_N / 8; i++)
        hash[i] = hash0[i] ^ hash1[i];
    int i, b = r * DIGITBITS;
    for (i = 0; i < b / 8; i++)
        if (hash[i])
            return 1;//POW_NONZERO_XOR;
    if ((b % 8) && hash[i] >> (8 - (b % 8)))
        return 1;//POW_NONZERO_XOR;
    return 0;//POW_OK;
}

int scanhash_equihash(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t hash32[8];
	int n = first_nonce;

	uint32_t solutions[20][512];


    equihash_thread_arg_t thread_args;
	blake2b_state curr_state;
    equihash_init_buckets(&thread_args.src, &thread_args.dst, &thread_args.indices);

	double t1 = get_tttime();

	do {
		//pdata 0-15 block header
		create_header(&curr_state, pdata, 4*16, n);
	    thread_args.state = curr_state;
		n_solutions += equihash(solutions, &thread_args.state, thread_args.src, thread_args.dst, thread_args.indices);

	  	//threaded_equihash(&thread_args);

		int ret = verifyrec(&curr_state, solutions, hash32, EQUIHASH_K); //TODO was ist r?
		if(ret == 1){
			printf("POW_NONZERO_XOR\n");
		}
		else if (ret == 2){
			printf("POW_OUT_OF_ORDER\n");
		}

		if (hash32[7] < Htarg && fulltest(hash32, ptarget)) {
			work_set_target_ratio(work, hash32);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	double ttot = get_tttime() - t1;

    printf("total solutions: %zu in (%f)\n", n - first_nonce, ttot);

    free(thread_args.src);
    free(thread_args.dst);
    for (size_t j = 0; j < 8/*TODO 9? warum kommt dann ein error*/; j++) {
     	free(thread_args.indices[j]);
    }
    free(thread_args.indices);

	return 0;
}
