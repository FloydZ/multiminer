#ifndef __UINT256_H__
#define __UINT256_H__

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

typedef struct uint256{
    uint32_t pn[8];
}uint256;

//implemented in util.c
#endif
