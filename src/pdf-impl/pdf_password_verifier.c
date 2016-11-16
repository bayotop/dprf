#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

/* Requirements: libssl-dev
/
/ gcc -o pdf pdf_password_verifier.c -lssl -lcrypto
/ ./pdf password v r length p meta_encrypted id_length id u_length u o_length o [-v]
/    
/ Author: Martin Bajanik 
/ Date: 14.10.2016
/
/ TO DO: Implement owner password verification. 
*/

static int verbose = 0;

int verify(char *password, int v, int r, int length, int p, int meta_encrypted, int id_length, unsigned char *id_str,
    int u_length, unsigned char *u_str, int o_length, unsigned char *o_str);
int verify_user_r5(unsigned char *password, unsigned char *u, int u_length);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext);
int sha256(unsigned char *input, int input_length, unsigned char *output);
int md5(unsigned char *input, int input_length, unsigned char *output);
int get_initial_md5_hash(int r, int password_padding_length, unsigned char *pass, int o_length, unsigned char *o,
    int p, int id_length, unsigned char *id, int meta_encrypted, unsigned char *initial_hash);
int get_final_md5_hash(unsigned char padding[32], int id_length, unsigned char *id, unsigned char *output);
int encrypt_rc4(unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *ciphertext);
int pdf_compute_hardened_hash_r6(unsigned char *password, int pwlen, unsigned char salt[8], unsigned char *ownerkey, unsigned char hash[32]);
void print_hex(unsigned char *input, int len);
int verbose_print(char *print);
int utf8_to_utf16le(char *utf8, char **utf16, int *utf16_len);
int str_to_uchar(unsigned char **output, unsigned char *str);

int main(int argc, char *argv[]) {
    // All parameters except the -v switch are mandatory
    if (argc != 13 && argc != 14) {
         fprintf(stderr, "Usage: %s password v r length p meta_encrypted id_length id u_length u o_length o [-v]\n", argv[0]);
         exit(1);
    }

    if (argc == 14 && strcmp(argv[13], "-v") == 0) {
        verbose = 1;
    }

    if (verbose) {
        ERR_load_crypto_strings();
        (verify(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), argv[8], atoi(argv[9]), argv[10], atoi(argv[11]), argv[12])) 
         ? verbose_print("Correct password!\n") 
         : verbose_print("Incorrect password!\n");
        
        return 1;
    } else {
        return verify(argv[1], atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]), atoi(argv[6]), atoi(argv[7]), argv[8], atoi(argv[9]), argv[10], atoi(argv[11]), argv[12]);
    }
}

int verify(char *password, int v, int r, int length, int p, int meta_encrypted, int id_length, unsigned char *id_str, int u_length, unsigned char *u_str,
    int o_length, unsigned char *o_str) {

    // Convert input to binary data. It's not possible to pass binary data directly because of null bytes (\x00)
    // See execve(2) semantics for more information
    // This has as low as no impact on perfomance
    unsigned char id[id_length];
    unsigned char *idp = id;
    str_to_uchar(&idp, id_str);

    unsigned char u[u_length];
    unsigned char *up = u;
    str_to_uchar(&up, u_str);

    unsigned char o[o_length];
    unsigned char *op = o;
    str_to_uchar(&op, o_str);

    // The password padding as per PDF specification
    const int password_padding_length = 32;
    unsigned char password_padding[32] = { 
        0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08, 
        0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A };

    // This are the only possible combinations of version and revision as per PDF specification
    if ((v != 1 && v != 2 && v != 4 && v != 5) ||
        (v == 1 && r != 2) ||
        (v == 2 && r != 3) ||
        (v == 4 && r != 4) ||
        (v == 5 && (r != 5 && r != 6))) {
        verbose_print("Unsupported version and revision numbers.\n");
        return 0;
    }

    if (length % 8 != 0) {
        verbose_print("The encryption key length should be a multiple of 8.\n");
        return 0;
    }

    verbose_print("Checking: '");
    if (verbose) {
        fwrite(password, 1, strlen(password), stdout);
    }
    verbose_print("'\n");

    // 'New' (revision >= 5) algorithms are completly different. Revision 5 is actually the easiest to brute-force.
    // TO DO: Unicode support, should be enforced by encoding to UTF-8.
    if (r == 5) {
        return verify_user_r5(password, u, u_length);
    }

    if (r == 6) {
        unsigned char output_hash[32];
        pdf_compute_hardened_hash_r6(password, strlen(password), u + 32, 0, output_hash);

        verbose_print("Given hash:    ");
        print_hex(u, 32);
        verbose_print("Computed hash: ");
        print_hex(output_hash, 32);

        int i;
        for (i = 0; i < 32; i++) {
            if (u[i] != output_hash[i]) {
                return 0;
            }
        }

        return 1;
    }

    // revision r <= 4
    // Algorithm 2 (see Document management — Portable document format specification)
    unsigned char pass[password_padding_length];
    int pass_length = (strlen(password) <= 32) ? strlen(password) : 32;
    memcpy(pass, password, pass_length);
    memcpy(pass + pass_length, password_padding, password_padding_length - pass_length);

    verbose_print("Padded password: "); print_hex(pass, 32);

    unsigned char hash[MD5_DIGEST_LENGTH] = { 0 };
    get_initial_md5_hash(r, password_padding_length, pass, o_length, o, p, id_length, id, meta_encrypted, hash);

    verbose_print("Initial hash: "); print_hex(hash, length / 8);

    int length_in_bytes = length / 8;

    if (r >= 3) {
        int i;
        for (i = 0; i < 50; i++) {
            md5(hash, length_in_bytes, hash);
        }
    }

    unsigned char key[length_in_bytes];
    memcpy(key, hash, length_in_bytes);

    unsigned char ciphertext[32] = { 0 };
    if (r == 2) {
        // PDF 1.3
        encrypt_rc4(password_padding, password_padding_length, key, 5, ciphertext);
    } else if (r > 2 && r <= 4) {
        // PDF 1.4 - PDF 1.7
        unsigned char xor[32];
        get_final_md5_hash(password_padding, id_length, id, hash);
        encrypt_rc4(hash, MD5_DIGEST_LENGTH, key, length_in_bytes, ciphertext);
        int x; int i;
        for (x = 1; x <= 19; x++) {
            for (i = 0; i < length_in_bytes; i++)
                xor[i] = key[i] ^ x;
            encrypt_rc4(ciphertext, MD5_DIGEST_LENGTH, xor, length_in_bytes, ciphertext);
        }
        memcpy(ciphertext + 16, password_padding, 16);
    } 
    
    verbose_print("Given U value:  ");
    print_hex(u, u_length);
    verbose_print("Actual U value: ");
    print_hex(ciphertext, 32);

    int i;
    int boundary = r >= 3 ? 16 : 32;
    for (i = 0; i < boundary; i++) {
        if (u[i] != ciphertext[i]) {
            return 0;
        } 
    }

    return 1;
}

int verify_user_r5(unsigned char *password, unsigned char *u, int u_length) {
    unsigned char buffer[128 + 8]; // password + 8 bytes of U

    int pass_length = strlen(password);
    if (pass_length > 127) {
            pass_length = 127;
    }

    memcpy(buffer, password, pass_length);
    memcpy(buffer + pass_length, u + 32, 8);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256(buffer, pass_length + 8, hash);

    verbose_print("Given hash:    ");
    print_hex(u, SHA256_DIGEST_LENGTH);
    verbose_print("Computed hash: ");
    print_hex(hash, SHA256_DIGEST_LENGTH);

    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (u[i] != hash[i]) {
            return 0;
        } 
    }

    return 1;
}

/* This method is from Sumatra PDF and MuPDF which are under GPL (gathered from JtR source at: https://github.com/magnumripper/JohnTheRipper/)
/  This algorithm is undocumented by Adobe AFAIK. 
/  http://esec-lab.sogeti.com/posts/2011/09/14/the-undocumented-password-validation-algorithm-of-adobe-reader-x.html */
int pdf_compute_hardened_hash_r6(unsigned char *password, int pwlen, unsigned char salt[8], unsigned char *ownerkey, unsigned char hash[32])
{
    unsigned char data[(128 + 64 + 48) * 64];
    unsigned char block[64];
    int block_size = 32;
    int data_len = 0;
    int i, j, sum;

    SHA256_CTX sha256;
    SHA512_CTX sha384;
    SHA512_CTX sha512;
    AES_KEY aes;

    /* Step 1: calculate initial data block */
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, pwlen);
    SHA256_Update(&sha256, salt, 8);
    if (ownerkey)
            SHA256_Update(&sha256, ownerkey, 48);
    SHA256_Final(block, &sha256);

    for (i = 0; i < 64 || i < data[data_len * 64 - 1] + 32; i++)
    {
        /* Step 2: repeat password and data block 64 times */
        memcpy(data, password, pwlen);
        memcpy(data + pwlen, block, block_size);
        // ownerkey is always NULL
        // memcpy(data + pwlen + block_size, ownerkey, ownerkey ? 48 : 0);
        data_len = pwlen + block_size + (ownerkey ? 48 : 0);
        for (j = 1; j < 64; j++)
                memcpy(data + j * data_len, data, data_len);

        /* Step 3: encrypt data using data block as key and iv */
        AES_set_encrypt_key(block, 128, &aes);
        // aes_crypt_cbc(&aes, AES_ENCRYPT, data_len * 64, block + 16, data, data);
        AES_cbc_encrypt(data, data, data_len * 64, &aes, block + 16, AES_ENCRYPT);

        /* Step 4: determine SHA-2 hash size for this round */
        for (j = 0, sum = 0; j < 16; j++)
                sum += data[j];

        /* Step 5: calculate data block for next round */
        block_size = 32 + (sum % 3) * 16;
        switch (block_size)
        {
        case 32:
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, data, data_len * 64);
            SHA256_Final(block, &sha256);
                break;
        case 48:
            SHA384_Init(&sha384);
            SHA384_Update(&sha384, data, data_len * 64);
            SHA384_Final(block, &sha384);
                break;
        case 64:
            SHA512_Init(&sha512);
            SHA512_Update(&sha512, data, data_len * 64);
            SHA512_Final(block, &sha512);
            break;
        }
    }

    memset(data, 0, sizeof(data));
    memcpy(hash, block, 32);
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
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

int md5(unsigned char *input, int input_length, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md; 
    int md_len;

    md = EVP_md5();

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

int get_initial_md5_hash(int r, int password_padding_length, unsigned char *pass, int o_length, unsigned char *o,
                         int p, int id_length, unsigned char *id, int meta_encrypted, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md; 
    int md_len;

    md = EVP_md5();

    if  (!(mdctx = EVP_MD_CTX_create())) {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, pass, password_padding_length)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, o, o_length)) {
        handleErrors();
    }

    uint32_t p_bytes = (uint32_t)p;

    if (1 != EVP_DigestUpdate(mdctx, (unsigned char *)&p_bytes, 4)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, id, id_length)) {
        handleErrors();
    }

    unsigned char revision_4_hashing_data[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    if (r >= 4) {
        if (!meta_encrypted) {
            if (1 != EVP_DigestUpdate(mdctx, revision_4_hashing_data, 4)) {
                handleErrors();
            }
        }
    }

    if (1 != EVP_DigestFinal_ex(mdctx, output, &md_len)) {
        handleErrors();
    }

    EVP_MD_CTX_destroy(mdctx);
    return md_len;
}

int get_final_md5_hash(unsigned char padding[32], int id_length, unsigned char *id, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md; 
    int md_len;

    md = EVP_md5();

    if  (!(mdctx = EVP_MD_CTX_create())) {
        handleErrors();
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, padding, 32)) {
        handleErrors();
    }

    if (1 != EVP_DigestUpdate(mdctx, id, id_length)) {
        handleErrors();
    }


    if (1 != EVP_DigestFinal_ex(mdctx, output, &md_len)) {
        handleErrors();
    }

    EVP_MD_CTX_destroy(mdctx);
    return md_len;
}

int encrypt_rc4(unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    if (key_len == 5) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4_40(), NULL, key, NULL)) {
            handleErrors();
        }
    } else {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL)) {
            handleErrors();
        }
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handleErrors();
    }

    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handleErrors();
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
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

// Converts an ASCII Hex string to an array of bytes
// "aabbccddeeff" => { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }
int str_to_uchar(unsigned char **output, unsigned char *str) {
    BIGNUM *input = BN_new();
    int input_len = BN_hex2bn(&input, str);
    input_len = (input_len + 1) / 2; // BN_hex2bn() returns number of hex digits
    BN_bn2bin(input, *output);
    
    BN_free(input);
    
    return input_len;
 }
