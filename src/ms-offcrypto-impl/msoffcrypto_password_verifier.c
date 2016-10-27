#include <iconv.h>
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
/ ./msoffcrypto password salt salt_length encrypted_verifier encrypted_verifier_length encrypted_verifier_hash encrypted_verifier_hash_length [-v]
/    
/ Author: Martin Bajanik 
/ Date: 23.08.2016
*/

static int verbose = 0;

int verify(char *password, unsigned char *salt, int salt_len, unsigned char *encrypted_verifier, int encrypted_verifier_len, 
    unsigned char *encrypted_verifier_hash, int encrypted_verifier_hash_len, int aes_key_length, int verifier_hash_size);
void handleErrors(void);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext);
int sha1(unsigned char *input, int input_length, unsigned char *output);
void print_hex(unsigned char *input, int len);
int verbose_print(char *print);
int utf8_to_utf16le(char *utf8, char **utf16, int *utf16_len);
int str_to_uchar(unsigned char **output, unsigned char *str);


int main(int argc, char *argv[]) {
    // All parameters except the -v switch are mandatory
    if (argc != 10 && argc != 11) {
         fprintf(stderr, "Usage: %s password salt salt_length encrypted_verifier encrypted_verifier_length \
            encrypted_verifier_hash encrypted_verifier_hash_length aes_key_length verifier_hash_size [-v]\n", argv[0]);
         exit(1);
    }

    if (argc == 11 && strcmp(argv[10], "-v") == 0) {
        verbose = 1;
    }

    if (verbose) {
        ERR_load_crypto_strings();
        (verify(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), argv[6], atoi(argv[7]), atoi(argv[8]), atoi(argv[9]))) 
         ? verbose_print("Correct password!\n") 
         : verbose_print("Incorrect password!\n");
        
        return 1;
    } else {
        return verify(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), argv[6], atoi(argv[7]), atoi(argv[8]), atoi(argv[9]));
    }
}

int verify(char *password, unsigned char *salt_str, int salt_len, unsigned char *encrypted_verifier_str, int encrypted_verifier_len, 
    unsigned char *encrypted_verifier_hash_str, int encrypted_verifier_hash_len, int aes_key_length, int verifier_hash_size) {

    // Convert input to binary data. It's not possible to pass binary data directly because of null bytes (\x00)
    // See execve(2) semantics for more information
    // This has as low as no impact on perfomance
    unsigned char salt[salt_len];
    unsigned char *s = salt;
    str_to_uchar(&s, salt_str);

    unsigned char encrypted_verifier[encrypted_verifier_len];
    unsigned char *ev = encrypted_verifier;
    str_to_uchar(&ev, encrypted_verifier_str);

    unsigned char encrypted_verifier_hash[encrypted_verifier_hash_len];
    unsigned char *evh = encrypted_verifier_hash;
    str_to_uchar(&evh, encrypted_verifier_hash_str);

    // Prepare the input. We need to string in UTF16LE encoding
    int input_length = strlen(password);

    char *pass = NULL;
    int input_length_utf16;

    if (!utf8_to_utf16le(password, &pass, &input_length_utf16)) {
        fprintf(stderr, "Error converting password to UTF16LE.\n");
        exit(1);
    }

    verbose_print("Checking: '");
    if (verbose) {
        fwrite(pass, 1, input_length_utf16, stdout);
    }
    verbose_print("'\n");

    // Initial hashing (H0 = SHA1(SALT + PASSWORD) -> Hn = SHA1(i + (Hn - 1)) (50000x) -> HFinal = SHA1(H50000 + BLOCK))
    size_t length = input_length_utf16;

    unsigned char *initial_input = calloc(salt_len + length, sizeof(char));
    memcpy(initial_input, salt, 16);
    memcpy(initial_input + 16, pass, length);

    free(pass);

    unsigned char hash[SHA_DIGEST_LENGTH];
    sha1(initial_input, salt_len + length, hash);

    free(initial_input);

    unsigned int i; // MS-OFFCRYPTO specifies 'i' as unsiogned 32-bit value (hashing purposes)
    unsigned char *p = (unsigned char*)&i;
    unsigned char *temp = calloc(sizeof(int) + SHA_DIGEST_LENGTH, sizeof(char));
    for (i = 0; i < 50000; i++) {
        memcpy(temp, p, sizeof(int));
        memcpy(temp + sizeof(int), hash, SHA_DIGEST_LENGTH);
        int j;
        SHA1(temp, SHA_DIGEST_LENGTH + sizeof(int), hash);
    }

    unsigned char block[sizeof(int)] = {0, 0, 0, 0};
    memcpy(temp, hash, SHA_DIGEST_LENGTH);
    memcpy(temp + SHA_DIGEST_LENGTH, block, sizeof(block));
    sha1(temp, SHA_DIGEST_LENGTH + sizeof(int), hash);

    free(temp);

    verbose_print("Final hash: ");
    print_hex(hash, SHA_DIGEST_LENGTH);

    // According to specification (MS-OFFCRYPTO) we should concatenate x1 and x2 and take first cbRequiredKeyLength only
    // However, because AES-128 is used, only the first 16 bytes are relevant, and x1 is 20 bytes long there for we do not need x2

    char x1temp[64] = { [0 ... 63] = 0x36 };
    // char x2temp[64] = { [0 ... 63] = 0x5c };

    // Here SHA_DIGEST_LENGTH is actually cbHash according to (MS-OFFCRYPTO)
    int x;
    for (x = 0; x < SHA_DIGEST_LENGTH; x++) {
        x1temp[x] ^= hash[x];
    }

    unsigned char x1[SHA_DIGEST_LENGTH];
    sha1(x1temp, 64, x1);

    /* for (x = 0; x < SHA_DIGEST_LENGTH; x++) {
        x2temp[x] ^= hash[x];
    }

    unsigned char x2[SHA_DIGEST_LENGTH];
    sha1(x2temp, 64, x2); */

    verbose_print("X1: ");
    print_hex(x1, SHA_DIGEST_LENGTH);
    /* verbose_print("X2: ");
    print_hex(x2, SHA_DIGEST_LENGTH); */

    unsigned char finalKey[aes_key_length / 8];
    memcpy(finalKey, x1, aes_key_length / 8);

    verbose_print("Derived key: ");
    print_hex(finalKey, aes_key_length / 8);

    // Attempt to decrypt the verifier values
    unsigned char decryptedVerifier[128];
    unsigned char decryptedVerifierHash[128];

    int decryptedVerifier_len = decrypt(encrypted_verifier, encrypted_verifier_len, finalKey, decryptedVerifier);
    if (decryptedVerifier_len != 16) {
        return 0;
    }

    int decryptedVerifierHash_len = decrypt(encrypted_verifier_hash, encrypted_verifier_hash_len, finalKey, decryptedVerifierHash);
    if (decryptedVerifierHash_len != 32 || decryptedVerifierHash[verifier_hash_size] != 0x00) {
        // Only the first 20 bytes are relevant as SHA1 is used to hash the verifier
        // Therefore the last 12 bytes have to be 0
        return 0;           
    }
    
    unsigned char verifierHash[SHA_DIGEST_LENGTH];
    sha1(decryptedVerifier, decryptedVerifier_len, verifierHash);

    verbose_print("Decrypted 'EncryptedVerifier' hash: ");
    print_hex(verifierHash, SHA_DIGEST_LENGTH);
    verbose_print("Decrypted 'EncryptedVerifierHash':  ");
    print_hex(decryptedVerifierHash, SHA_DIGEST_LENGTH);

    // Actually if in the previous check the last 12 bytes of the decrypted verifier hash are 0,
    // this check could be ommited for performance reasons
    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        if (verifierHash[i] != decryptedVerifierHash[i]) {
            return 0;
        } 
    }

    return 1;
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) { 
        handleErrors(); 
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL)) {
        handleErrors();
    }

    if (1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        handleErrors();
    }

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

int sha1(unsigned char *input, int input_length, unsigned char *output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md; 
    int md_len;

    md = EVP_sha1();

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

// http://stackoverflow.com/questions/13297458/simple-utf8-utf16-string-conversion-with-iconv
int utf8_to_utf16le(char *utf8, char **utf16, int *utf16_len)
{
    iconv_t cd;
    char *inbuf, *outbuf;
    size_t inbytesleft, outbytesleft, nchars, utf16_buf_len;

    cd = iconv_open("UTF16LE", "UTF8");
    if (cd == (iconv_t) - 1) {
        printf("!%s: iconv_open failed: %d\n", __func__, errno);
        return -1;
    }

    inbytesleft = strlen(utf8);
    if (inbytesleft == 0) {
        printf("!%s: empty string\n", __func__);
        iconv_close(cd);
        return -1;
    }

    inbuf = utf8;
    utf16_buf_len = 2 * inbytesleft;
    *utf16 = malloc(utf16_buf_len);
    if (!*utf16) {
        printf("!%s: malloc failed\n", __func__);
        iconv_close(cd);
        return -1;
    }

    outbytesleft = utf16_buf_len;
    outbuf = *utf16;

    nchars = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    while (nchars == (size_t) - 1 && errno == E2BIG) {
        char *ptr;
        size_t increase = 10;
        size_t len;
        utf16_buf_len += increase;
        outbytesleft += increase;
        ptr = realloc(*utf16, utf16_buf_len);
        if (!ptr) {
            printf("!%s: realloc failed\n", __func__);
            free(*utf16);
            iconv_close(cd);
            return -1;
        }
        len = outbuf - *utf16;
        *utf16 = ptr;
        outbuf = *utf16 + len;
        nchars = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    }
    if (nchars == (size_t) - 1) {
        printf("!%s: iconv failed: %d\n", __func__, errno);
        free(*utf16);
        iconv_close(cd);
        return -1;
    }

    iconv_close(cd);
    *utf16_len = utf16_buf_len - outbytesleft;

    return 1;
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