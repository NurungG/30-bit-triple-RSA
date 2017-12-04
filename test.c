#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include "xxhash.h"

#define KEY_SIZE 30
#define GEN_MAX 1024

#define TEST_SIZE 20
#define COMPOSITE 0
#define PRIME 1

typedef int32_t int32;
typedef int64_t int64;

int32 getRandomPrime();
int32 getPublicKey(int32, int32);
int32 getPrivateKey(int32, int32);

int32 getHash(int, int32);

int32 RSA_Encryption(int32, int32, int32);
int32 RSA_Decryption(int32, int32, int32);

int32 generateSignature(int32, int32, int32);
int32 verifySignature(int32, int32, int32);

int32 is_prime(int32);
int32 exp_sqrmul(int32, int32, int32);
int32 gcd(int32, int32);

int main() {
	int32 p, q, r;
	int32 N, phi, e, d;
	int32 plain, cipher, decrypt, signature;
	int32 hash, decrypt_hash, verify;

	srand((unsigned)time(NULL));
	
	p = 911;//getRandomPrime();
	q = 977;//getRandomPrime();
	r = 691;//getRandomPrime();

	printf("p = %d\n", p);
	printf("q = %d\n", q);
	printf("r = %d\n", r);

	N = p * q * r;
	phi = (p - 1) * (q - 1) * (r - 1);

	printf("N = %d\n", N);
	printf("phi = %d\n", phi);

	e = 27737;//getPublicKey(N, phi);
	d = getPrivateKey(e, phi);

	printf("e = %d\n", e);
	printf("d = %d\n\n", d);

	printf("Message Input : ");
	scanf("%d", &plain);
	printf("Message : %d\n\n", plain);

	puts("**Encryption");
	cipher = RSA_Encryption(plain, e, N);
	printf("cipher : %d\n\n", cipher);

	puts("**Generate signature");
	hash = getHash(plain, N);
	printf("message's hash value : %d\n", hash);
	signature = generateSignature(hash, d, N);
	printf("generated signature :  %d\n\n\n", signature);

	puts("**Decryption");
	decrypt = RSA_Decryption(cipher, d, N);
	printf("decrypted cipher : %d\n\n", decrypt);

	puts("**Verigy signature");
	printf("received signature value : %d\n", signature);
	decrypt_hash = getHash((long)decrypt, N);
	printf("decrypted message's hash value : %d\n", decrypt_hash);
	verify = verifySignature(signature, e, N);
	printf("verify value from signature : %d\n", verify);

	if (decrypt_hash == verify) {
		puts("Signature valid!");
	} else {
		puts("Signature not valid!");
	}


	return 0;
}

int32 getRandomPrime() {
	int32 gen;
	while (1) {
		gen = rand() % GEN_MAX;
		if(is_prime(gen)) {
			return gen;
		}
	}
}

int32 getPublicKey(int32 N, int32 phi) {
	int32 e;
	while (1) {
		e = rand() % phi;

		if (gcd(e, phi) == 1) {
			return e;
		}
	}
}

int32 getPrivateKey(int32 e, int32 phi) {
	int32 d, p0, p1;
	int32 q, r;
	int32 a, b;

	a = phi; b = e;
	p0 = 0; p1 = 1;
	while (1) {
		q = a / b;
		r = a % b;

		if (r == 0) {
			return (d > 0) ? d : d + phi;
		}

		d = (p0 - (p1 * q)) % phi;
		
		a = b;
		b = r;
		p0 = p1;
		p1 = d;
	}
}

int32 getHash(int msg, int N) {
	uint64_t hash;
	char buf[65];
	printf("%lu\n", (uint64_t)msg);
	sprintf(buf, "%lu", (uint64_t)msg);
	hash = XXH64(buf, sizeof(buf) - 1, 0);
	printf("%lu\n", hash);
	
	hash = hash % N;
	return hash;
}

int32 RSA_Encryption(int32 msg, int32 e, int32 N) {
	return exp_sqrmul(msg, e, N);
}

int32 RSA_Decryption(int32 cipher, int32 d, int32 N) {
	return exp_sqrmul(cipher, d, N);
}

int32 generateSignature(int32 hash, int32 d, int32 N) {
	return exp_sqrmul(hash, d, N);
}

int32 verifySignature(int32 signature, int32 e, int32 N) {
	return exp_sqrmul(signature, e, N);
}

int32 is_prime(int32 n) {
	// Based on Miller-Rabin algorithm
	
	int i, j;
	int k, q, a;

	// Return if it's even number
	if (n % 2 == 0) {
		return COMPOSITE;
	}

	// Init values
	k = 0;
	q = n - 1;

	// Get k and q ( n-1 = (2^k)*q )
	while (q % 2 == 0) {
		q /= 2;
		++k;
	}

	// Miller-Rabin algorithm
	for (i = 0; i < TEST_SIZE; i++) {
		a = (rand() % (n - 3)) + 2;

		if (exp_sqrmul(a, q, n) == 1) { // Pass the test
			continue;
		}

		for (j = 0; j < k; j++) {
			if (exp_sqrmul(a, pow(2, j) * q, n) == n - 1) {
				// Pass the test
				break;
			}
		}
		if (j != k) {
			continue;
		}

		// Composite
		break;
	}

	if (i == 20) {
		return PRIME;
	} else {
		return COMPOSITE;
	}
}

int32 exp_sqrmul(int32 a, int32 b, int32 mod) {
	int i;
	int msb;
	int ret;

	ret = 1;

	for (i = 0; i < KEY_SIZE; i++) {
		if ((b >> i) & 1) {
			msb = i;
		}
	}

	for (i = 0; i <= msb; i++) {
		if ((b >> i) & 1) {
			ret = ((int64)ret * (int64)a) % mod;
		}
		a = ((int64)a * (int64)a) % mod;
	}
	
	return (ret > 0) ? ret : ret + mod;
}

int32 gcd(int32 a, int32 b) {
	if (b == 0) return a;
	return gcd(b, a % b);
}

