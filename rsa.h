#ifndef __RSA_H__
#define __RSA_H__

/* Includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "xxhash.h"

/* Define */
#define KEY_SIZE 30
#define GEN_MAX 1024

#define TEST_SIZE 20
#define COMPOSITE 0
#define PRIME 1

typedef int32_t int32;
typedef int64_t int64;

/* Funtions */
int32 getRandomPrime();
int32 getPublicKey(int32, int32);
int32 getPrivateKey(int32, int32);

int32 getHash(int32, int32);

int32 RSA_Encryption(int32, int32, int32);
int32 RSA_Decryption(int32, int32, int32);

int32 generateSignature(int32, int32, int32);
int32 verifySignature(int32, int32, int32);


#endif