#include "rsa.h"
#include <time.h>

int main() {
	int32 p, q, r;
	int32 N, phi, e, d;
	int32 plain, cipher, decrypt, signature;
	int32 hash, decrypt_hash, verify;

	srand((unsigned)time(NULL));

	// Get random prime & print
	p = 911;// getRandomPrime();
	q = 977;// getRandomPrime();
	r = 691;// getRandomPrime();
	printf("p = %d\n", p);
	printf("q = %d\n", q);
	printf("r = %d\n", r);

	// Compute their system modulus & print
	N = p * q * r;
	phi = (p - 1) * (q - 1) * (r - 1);
	printf("N = %d\n", N);
	printf("phi = %d\n", phi);

	// Select at random the encrytion key & print
	e = 27737;// getPublicKey(N, phi);
	d = getPrivateKey(e, phi);
	printf("e = %d\n", e);
	printf("d = %d\n\n", d);

	// Get message (standard input)
	printf("Message Input : ");
	scanf("%d", &plain);
	printf("Message : %d\n\n", plain);

	/* Send message */
	// RSA encryption
	puts("**Encryption");
	cipher = RSA_Encryption(plain, e, N);
	printf("cipher : %d\n\n", cipher);

	// Send with generated signature
	puts("**Generate signature");
	hash = getHash(plain, N);
	printf("message's hash value : %d\n", hash);
	signature = generateSignature(hash, d, N);
	printf("generated signature :  %d\n\n\n", signature);

	/* Receive message */
	// RSA decryption
	puts("**Decryption");
	decrypt = RSA_Decryption(cipher, d, N);
	printf("decrypted cipher : %d\n\n", decrypt);

	// Verify signature
	puts("**Verify signature");
	printf("received signature value : %d\n", signature);
	decrypt_hash = getHash(decrypt, N);
	printf("decrypted message's hash value : %d\n", decrypt_hash);
	verify = verifySignature(signature, e, N);
	printf("verify value from signature : %d\n", verify);

	// Validation test
	if (decrypt_hash == verify) {
		puts("Signature valid!");
	} else {
		puts("Signature not valid!");
	}

	return 0;
}
