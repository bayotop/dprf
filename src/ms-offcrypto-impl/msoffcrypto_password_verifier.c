#include <errno.h>
#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// gcc -lssl -lcrypto -o msoffcrypto msoffcrypto_password_verifier.c
// ./msoffcrypto password

// TO DO:  SHA1() is deprecated, use EVP interface
// 		   ALL hard-coded stuff needs to be delete -> provide CLI
//         Use valgrind and free() all the stuff
//		   Refactor string conversion to UTF16LE into a robust method


int AES_128_KEYSIZE = 16;
unsigned char *ENCRYPTED_VERIFIER_TO_CHECK = "189576350e7b9f3c8c74b65e755417c2";
unsigned char *ENCRYPTED_VERIFIER_HASH_TO_CHECK = "31c1ed3848d9f0b05d52b2249d357fc51eb39b62823699226284f20f960fd12f";

void print_hex(unsigned char *input, int len);
int str_to_uchar(unsigned char **output, unsigned char *str);

int main(int argc, char *argv[]) {
	if (!argv[1]) {
		printf("Usage: ./script password\n");
		return -1;
	} 

	verify(argv[1]);
	return 0;
}

int verify(char *password) {
	int input_length = strlen(password);
	int input_length_utf16 = 2*input_length;

	char *output = calloc(input_length_utf16, sizeof(char));
	char *output_start = output;

	size_t inbytesleft = input_length;
	size_t outbytesleft = input_length_utf16;

 	iconv_t cd = iconv_open("UTF16LE", "ASCII");
	iconv(cd, &password, &inbytesleft, &output, &outbytesleft);
	iconv_close(cd);

	printf("Checking: '");
	fwrite(output_start, 1, input_length_utf16, stdout);
	printf("'\n");

	size_t length = input_length_utf16;

	unsigned char salt[16] = { 0xde, 0x40, 0xab, 0xf5, 0xf6, 0x22, 0x7d, 0x08, 0x07, 0x4a,
							   0x8f, 0x15, 0x79, 0xcd, 0x18, 0x3a };

	unsigned char *initial_input = calloc(sizeof(salt) + length, sizeof(char));
	memcpy(initial_input, salt, 16);
	memcpy(initial_input + 16, output_start, length);

	free(output_start);

	unsigned char hash[SHA_DIGEST_LENGTH];
	SHA1(initial_input, sizeof(salt) + length, hash);

	free(initial_input);

	unsigned int i; // ms-offcrypto specifies i as unsiogned 32-bit value (hashing purposes)
	unsigned char *p = (unsigned char*)&i;
	unsigned char *temp = calloc(sizeof(int) + SHA_DIGEST_LENGTH, sizeof(char));
	for(i = 0; i < 50000; i++) {
		memcpy(temp, p, sizeof(int));
		memcpy(temp + sizeof(int) , hash, SHA_DIGEST_LENGTH);
		int j;
		SHA1(temp, SHA_DIGEST_LENGTH + sizeof(int), hash);
	}

	unsigned char block[sizeof(int)] = {0, 0, 0, 0};
	memcpy(temp, hash, SHA_DIGEST_LENGTH);
	memcpy(temp + SHA_DIGEST_LENGTH, block, sizeof(block));
	SHA1(temp, SHA_DIGEST_LENGTH + sizeof(int), hash);

	free(temp);

	printf("Final hash: ");
	print_hex(hash, SHA_DIGEST_LENGTH);

	char x1temp[64] = { [0 ... 63] = 0x36 };
	char x2temp[64] = { [0 ... 63] = 0x5c };

	// Here 2 is cbHash (MS-OFFCRYPTO)
	int x;
	for (x = 0; x < 20; x++) {
		x1temp[x] ^= hash[x];
	}


	unsigned char x1[SHA_DIGEST_LENGTH];
	SHA1(x1temp, 64, x1);

	for (x = 0; x < 20; x++) {
		x2temp[x] ^= hash[x];
	}

	unsigned char x2[SHA_DIGEST_LENGTH];
	SHA1(x2temp, 64, x2);

	printf("X1: ");
	print_hex(x1, SHA_DIGEST_LENGTH);
	printf("X2: ");
	print_hex(x2, SHA_DIGEST_LENGTH);

	// TODO: Concatenate x1 and x2 and take first cbRequiredKeyLength only. (MS-OFFCRYPTO)

	unsigned char finalKey[AES_128_KEYSIZE];
	memcpy(finalKey, x1, AES_128_KEYSIZE);

	printf("Derived key: ");
	print_hex(finalKey, AES_128_KEYSIZE);

	// VERIFICATION
	unsigned char *encrypted_verifier = (unsigned char*)malloc(16);
	int encrypted_verifier_len = str_to_uchar(&encrypted_verifier, ENCRYPTED_VERIFIER_TO_CHECK);

	unsigned char *encrypted_verifier_hash = (unsigned char*)malloc(32);
	int encrypted_verifier_hash_len = str_to_uchar(&encrypted_verifier_hash, ENCRYPTED_VERIFIER_HASH_TO_CHECK);

	unsigned char decryptedVerifier[128];
	unsigned char decryptedVerifierHash[128];

	ERR_load_crypto_strings();
  	OpenSSL_add_all_algorithms();
  	OPENSSL_config(NULL);

  	int decryptedVerifier_len = decrypt(encrypted_verifier, encrypted_verifier_len, finalKey, decryptedVerifier);
  	int decryptedVerifierHash_len = decrypt(encrypted_verifier_hash, encrypted_verifier_hash_len, finalKey, decryptedVerifierHash);

	free(encrypted_verifier); free(encrypted_verifier_hash);
  	
  	unsigned char verifierHash[SHA_DIGEST_LENGTH];
	SHA1(decryptedVerifier, decryptedVerifier_len, verifierHash);

	printf("Decrypted 'EncryptedVerifier' hash: ");
	print_hex(verifierHash, SHA_DIGEST_LENGTH);
	printf("Decrypted 'EcryptedVerifierHash':   ");
	print_hex(decryptedVerifierHash, SHA_DIGEST_LENGTH);

	return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
	handleErrors();

	EVP_CIPHER_CTX_set_padding(ctx, 0);

	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	handleErrors();
	plaintext_len = len;
	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void print_hex(unsigned char *input, int len)
{
	int i;
	for(i = 0; i < len; i++) {
    	printf("%02x", input[i]);
	}

	printf("\n");
}

int str_to_uchar(unsigned char **output, unsigned char *str)
{
	BIGNUM *input = BN_new();
	int input_len = BN_hex2bn(&input, str);
	input_len = (input_len + 1) / 2; // BN_hex2bn() returns number of hex digits
	BN_bn2bin(input, *output);

	BN_free(input);

	return input_len;
}