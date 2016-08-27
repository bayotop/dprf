#include <iconv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* Requirements: libssl-dev
/
/ gcc -o msoffcrypto msoffcrypto_password_verifier.c -lssl -lcrypto
/ ./msoffcrypto password
/
/ Author: Martin Bajanik 
/ Date: 27.08.2016
/
/ TO DO:  ALL hard-coded stuff needs to be delete -> provide CLI */

static int verbose = 0;

int verify(char *password);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int sha256(unsigned char *input, int input_length, unsigned char *output);
void print_hex(unsigned char *input, int len);
int str_to_uchar(unsigned char **output, unsigned char *str);
int verbose_print(char *print);
void parseArgs(int argc, char *argv[], char **password);

// Hard coded stuff  (information from encrypted ODT)
unsigned char *CHECKSUM = "9b4fb24edd6d1d8830e272398263cdbf026b97392cc35387b991dc0248a628f9";
unsigned char *IV = "e31dc53b13e5177b35455086dea287dd";
unsigned char *SALT = "399e6f2e5176f49f9958a108e3c212a3";
unsigned char *ENCRYPTED_FILE = "3cb21bb16fab6e820daeff44f60a58a1";

int main(int argc, char *argv[]) {

    char *password = NULL;
    parseArgs(argc, argv, &password);

    ERR_load_crypto_strings();

    if (verbose) {
        (verify(password)) ? verbose_print("Correct password!\n") : verbose_print("Incorrect password!\n");
        
        return 1;
    } else {
        return verify(password);
    }
}

int verify(char *password) {
    verbose_print("Checking: '");
    if (verbose) {
        fwrite(password, 1, strlen(password), stdout);
    }
    verbose_print("'\n");

	unsigned char start_key[SHA256_DIGEST_LENGTH];
	sha256(password, strlen(password), start_key);

	verbose_print("Starting key: ");
	print_hex(start_key, SHA256_DIGEST_LENGTH);

	unsigned char *salt = (unsigned char*)malloc(16);
	str_to_uchar(&salt, SALT);

	unsigned char derived_key[SHA256_DIGEST_LENGTH];
	PKCS5_PBKDF2_HMAC_SHA1(start_key, SHA256_DIGEST_LENGTH, salt, 16, 1024, 32, derived_key);

	free(salt);

	verbose_print("Derived key: ");
	print_hex(derived_key, 32);

	unsigned char *iv = (unsigned char*)malloc(16);
	str_to_uchar(&iv, IV);

	unsigned char *encrypted_file = (unsigned char*)malloc(strlen(ENCRYPTED_FILE)/2);
	int encrypted_file_len = str_to_uchar(&encrypted_file, ENCRYPTED_FILE);

	unsigned char decryptedFile[encrypted_file_len];

	int decryptedFile_len = decrypt(encrypted_file, encrypted_file_len, derived_key, iv, decryptedFile);

    free(iv);
    free(encrypted_file);

    /* This is a very unsafe password correctnes check. It assumes that the encrypted file for verification is 
    / /Configurations2/accelerator/current.xml which in many cases is an empty file with size 0. 
    / When deflated it becomes 0x03 0x00 (checksum: m0+yTt1tHYgw4nI5gmPNvwJrlzksw1OHuZHcAkimKPk="). 
    / From the specification it is not clear what padding scheme is used and I couldn't figure it out, yet. */
    if (decryptedFile_len == 16) {
    	verbose_print("Experimental password verification: ");
    	return decryptedFile[0] == 0x03 && decryptedFile[1] == 0x00;
    	verbose_print("\n");
    }

    if (decryptedFile_len > 1024) {
    	decryptedFile_len = 1024;
    }

    unsigned char temp[decryptedFile_len];
    memcpy(temp, decryptedFile, decryptedFile_len);
	unsigned char decryptedFileHash[SHA256_DIGEST_LENGTH];
    sha256(temp, decryptedFile_len, decryptedFileHash);

    unsigned char *checksum = (unsigned char*)malloc(SHA256_DIGEST_LENGTH);
	str_to_uchar(&checksum, CHECKSUM);

    verbose_print("Checksum:  ");
    print_hex(checksum, SHA256_DIGEST_LENGTH);
    verbose_print("Decrypted 'EncryptedFile' hash: ");
    print_hex(decryptedFileHash, SHA256_DIGEST_LENGTH);

    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (checksum[i] != decryptedFileHash[i]) {
        	free(checksum);
            return 0;
        } 
    }

    free(checksum);
    return 1;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) { 
        handleErrors(); 
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        handleErrors();
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int sha256(unsigned char *input, int input_length, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md; 
    int md_len;

    md = EVP_sha256();

    if  (!(mdctx = EVP_MD_CTX_create())) {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, input, input_length)) {
        handleErrors();
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output, &md_len)) {
        handleErrors();
    }

    EVP_MD_CTX_destroy(mdctx);
    return md_len;
}

void print_hex(unsigned char *input, int len) {
    if (verbose) {
        int i;
        for(i = 0; i < len; i++) {
            printf("%02x", input[i]);
        }

        verbose_print("\n");
    }
}

int str_to_uchar(unsigned char **output, unsigned char *str) {
    BIGNUM *input = BN_new();
    int input_len = BN_hex2bn(&input, str);
    input_len = (input_len + 1) / 2; // BN_hex2bn() returns number of hex digits
    BN_bn2bin(input, *output);

    BN_free(input);

    return input_len;
}

int verbose_print(char *print) {
    if (verbose) {
        printf(print);
    }
}

void parseArgs(int argc, char *argv[], char **password) {
    if (argc == 2) {
        *password = argv[1];

        return;
    }

    if (argc == 3 && (strcmp(argv[1], "-v") == 0)) {
        verbose = 1;
        *password = argv[2];

        return;
    }

    fprintf(stderr, "Usage: %s [-v] password\n", argv[0]);
    exit(1);
}