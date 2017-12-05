#include "rsa.h"

/* Private Functions */
static int32 exp_sqrmul(int32 a, int32 b, int32 mod) {
	// Do exponentiation, using Square and multiply algorithm for modular exponentiation.
	int i;
	int msb;
	int ret;

	ret = 1;

	// Get MSB of exponent
	for (i = 0; i < KEY_SIZE; i++) {
		if ((b >> i) & 1) {
			msb = i;
		}
	}

	// Exponentiation
	for (i = 0; i <= msb; i++) {
		if ((b >> i) & 1) {
			ret = ((int64)ret * (int64)a) % mod;
		}
		a = ((int64)a * (int64)a) % mod;
	}

	return (ret > 0) ? ret : ret + mod;
}

static int32 is_prime(int32 n) {
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

static int32 gcd(int32 a, int32 b) {
	// Get greatest common divisior
	if (b == 0) return a;
	return gcd(b, a % b);
}

static int32 getMulInverse(int32 b, int32 mod) {
	// Get multiplicative inverse (b, mod), using Extended Euclidean Algorithm
	int32 ret, p0, p1;
	int32 q, r;
	int32 a;

	// Init values
	a = mod;
	p0 = 0; p1 = 1;
	ret = p1;

	// Do Extended Euclidean Algorithm
	while (1) {
		// Do divide
		q = a / b;
		r = a % b;

		// If remainder is 0, return multiplicative inverse
		if (r == 0) {
			return (ret > 0) ? ret : ret + mod;
		}

		// Set the Euclidean number according to the ignition formula below
		// p[i] = p[i - 2] - p[i - 1] * q[i - 2] 
		ret = (p0 - (p1 * q)) % mod;

		// Set next round's values
		a = b;
		b = r;
		p0 = p1;
		p1 = ret;
	}
}



/* Public Functions */
int32 getRandomPrime() {
	// Generate random prime (less than 1024(GEN_MAX))
	int32 gen;
	while (1) {
		gen = rand() % GEN_MAX;
		if (is_prime(gen)) {
			return gen;
		}
	}
}

int32 getPublicKey(int32 phi) {
	// Select at random the encryption key 
	int32 e;
	while (1) {
		e = rand() % phi;

		// Until e is relatively prime to phi
		if (gcd(e, phi) == 1) {
			return e;
		}
	}
}

int32 getPrivateKey(int32 e, int32 phi) {
	// Find decryption key (find multiplicative inverse using (e, phi) with Extended Euclidean Algorithm)
	return getMulInverse(e, phi);
}

int32 getHash(int32 msg, int32 N) {
	// Hashing the msg, using xxhash function
	uint64_t hash;
	char buf[65];
	sprintf(buf, "%I64u", (uint64_t)msg);
	hash = XXH64(buf, sizeof(buf) - 1, 0);
	hash = hash % N;
	return (int32)hash;
}

int32 RSA_Encryption(int32 msg, int32 e, int32 N) {
	// Encrypt msg using public key (e, N)
	return exp_sqrmul(msg, e, N);
}

int32 RSA_Decryption(int32 cipher, int32 d, int32 N) {
	// Decrypt ciphertext using private key (d, N)
	return exp_sqrmul(cipher, d, N);
}

int32 generateSignature(int32 hash, int32 d, int32 N) {
	// Generate signature with hashed msg, using private key (d, N)
	return exp_sqrmul(hash, d, N);
}

int32 verifySignature(int32 signature, int32 e, int32 N) {
	// Decrypt signature to hashed msg (to verify), using public key (e, N)
	return exp_sqrmul(signature, e, N);
}
