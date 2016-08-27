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
/ gcc -o odt odt_password_verifier.c -lssl -lcrypto
/ ./odt password checksum iv salt encrypted_file encrypted_file_length [-v]
/
/ Author: Martin Bajanik 
/ Date: 27.08.2016 
*/

static int verbose = 0;

int verify(char *password, unsigned char *checksum, unsigned char *iv, unsigned char *salt, unsigned char* encrypted_file, int encrypted_file_len);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);
int sha256(unsigned char *input, int input_length, unsigned char *output);
void print_hex(unsigned char *input, int len);
int verbose_print(char *print);

int main(int argc, char *argv[]) {

    if (argc != 7 && argc != 8) {    
        fprintf(stderr, "Usage: %s password checksum iv salt encrypted_file encrypted_file_length [-v]\n", argv[0]);
        exit(1);
    }

    if (argc == 8 && strcmp(argv[7], "-v") == 0) {
        verbose = 1;
    }

    if (verbose) {
        ERR_load_crypto_strings();
        (verify(argv[1], argv[2], argv[3], argv[4], argv[5], atoi(argv[6]))) ? verbose_print("Correct password!\n") : verbose_print("Incorrect password!\n");
        
        return 1;
    } else {
        return verify(argv[1], argv[2], argv[3], argv[4], argv[5], atoi(argv[6]));
    }
}

int verify(char *password, unsigned char *checksum, unsigned char *iv, unsigned char *salt, unsigned char* encrypted_file, int encrypted_file_len) {
    verbose_print("Checking: '");
    if (verbose) {
        fwrite(password, 1, strlen(password), stdout);
    }
    verbose_print("'\n");

	unsigned char start_key[SHA256_DIGEST_LENGTH];
	sha256(password, strlen(password), start_key);

	verbose_print("Starting key: ");
	print_hex(start_key, SHA256_DIGEST_LENGTH);

	unsigned char derived_key[SHA256_DIGEST_LENGTH];
	PKCS5_PBKDF2_HMAC_SHA1(start_key, SHA256_DIGEST_LENGTH, salt, 16, 1024, 32, derived_key);

	verbose_print("Derived key: ");
	print_hex(derived_key, 32);

	unsigned char decryptedFile[encrypted_file_len];

	int decryptedFile_len = decrypt(encrypted_file, encrypted_file_len, derived_key, iv, decryptedFile);

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

int verbose_print(char *print) {
    if (verbose) {
        printf(print);
    }
}