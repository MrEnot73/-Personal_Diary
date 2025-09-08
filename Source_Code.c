#include "encrypt.h"
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <wincrypt.h>
#include <direct.h>
#define TRIES 3
#define MAX_PASSWORD 1024
#define CREATE_FILE_ERROR -1
#define WRITE_FILE_ERROR -2
#define WRONG_PASSWORD -3
#define OPEN_FILE_ERROR -4
#define SALT_IN_SIZE 32
#define ASCII_SIZE 128
#define PASSWORD_HASH_SIZE 64
static const char* aut_salt_place = "D:/Blocknote_Protection/aut_salt.txt";
static const char* enc_salt_place = "D:/Blocknote_Protection/enc_salt.txt";
static const char* kdf_hash_place = "D:/Blocknote_Protection/kdf_hash.txt";
static const char* hmac_hash_place = "D:/Blocknote_Protection/hmac_hash.txt";
static const char* blocknote_place = "D:/Blocknote_Protection/blocknote.txt";
static const char* session_key_place = "D:/Blocknote_Protection/session_key.txt";
char password[MAX_PASSWORD], key[MAX_PASSWORD], kbuff[BUFSIZ], bbuff[BUFSIZ];
uint8_t hmac_hash[SOUTBUFF * 4 + PASSWORD_HASH_SIZE * 2 + 1], hash_password[PASSWORD_HASH_SIZE * 2 + 1];
void clear_info()
{
    memset(password, 0, sizeof(password));
    memset(key, 0, sizeof(key));
    memset(hash_password, 0, sizeof(hash_password));
    memset(hmac_hash, 0, sizeof(hmac_hash));
    memset(kbuff, 0, sizeof(kbuff));
    memset(bbuff, 0, sizeof(bbuff));
}
void mperror(const char *error, int status)
{
    fprintf(stderr, "error: %s\n", error);
    clear_info();
    exit(status);
}
uint8_t *secure_random_bytes(uint8_t *buf, size_t size) 
{
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        mperror("CryptAcquireContext failed", -1);
    if (!CryptGenRandom(hProv, size, buf))
        mperror("CryptGenRandom failed", -1);
    CryptReleaseContext(hProv, 0);
    return buf;
}
uint8_t *generate_salt(uint8_t *salt_out)
{
    static uint8_t salt_in[SALT_IN_SIZE];
    secure_random_bytes(salt_in, SALT_IN_SIZE);
    return sha256(salt_in, SALT_IN_SIZE, salt_out);
}
void delete_info(char *txt)
{
    unlink(aut_salt_place);
    unlink(enc_salt_place);
    unlink(kdf_hash_place);
    unlink(hmac_hash_place);
    unlink(blocknote_place);
    unlink(session_key_place);
    mperror(txt, WRONG_PASSWORD);
}
void check_salt(const char *place, uint8_t *buff)
{
    static uint8_t salt[SOUTBUFF];
    FILE *fp;
    int i, c;
    if((fp = fopen(place, "r")) == NULL)
    {
        if((fp = fopen(place, "w")) == NULL)
            mperror("can't creat a salt file", CREATE_FILE_ERROR);
        generate_salt(salt);
        for(i = 0; i < SOUTBUFF; ++i)
            sprintf(buff + i * 2, "%02x", salt[i]);
        i = fprintf(fp, "%s", buff);
    }
    else
        for(i = 0; (c = getc(fp)) != EOF;)
            buff[i++] = c;
    fclose(fp);
    if(i == -1)
        mperror("can't write in salt file", WRITE_FILE_ERROR);
}
int main()
{
    srand(time(NULL));
    int i, c, kfd, bfd, n, j, mod, tries = TRIES;
    uint8_t salt[SOUTBUFF * 2], *ptr;
    FILE *fp;
    _mkdir("D:/Blocknote_Protection");
    start:
    check_salt(aut_salt_place, hmac_hash);
    check_salt(enc_salt_place, hmac_hash + SOUTBUFF * 2);
    strncpy(salt, hmac_hash + SOUTBUFF * 2, SOUTBUFF * 2);
    do
    {
        printf("Input password (max length %d): ", MAX_PASSWORD - 2);
    } while (fgets(password, MAX_PASSWORD, stdin) == NULL);
    password[strlen(password) - 1] = 0;
    pbkdf2_hmac_sha256(password, strlen(password), hmac_hash, SOUTBUFF * 2, 100000, PASSWORD_HASH_SIZE, hash_password);
    ptr = hmac_hash + SOUTBUFF * 4;
    for(i = 0; i < PASSWORD_HASH_SIZE; ++i)
        sprintf(ptr + i * 2, "%02x", hash_password[i]);
    if((fp = fopen(kdf_hash_place, "r")) == NULL)
    {
        if((fp = fopen(kdf_hash_place, "w")) == NULL)
            mperror("can't create a kdf hash file", CREATE_FILE_ERROR);
        i = fprintf(fp, "%s", ptr);
        fclose(fp);
        if(i == -1)
            mperror("can't write in kdf hash file", WRITE_FILE_ERROR);
    }
    else
    {
        for(i = 0; i < PASSWORD_HASH_SIZE * 2 && (c = getc(fp)) != EOF;)
            hash_password[i++] = c;
        hash_password[i] = 0;
        fclose(fp);
        if(strcmp(ptr, hash_password))
        {
            if(--tries > 0)
            {
                printf("wrong password. You have %d tries.\n", tries);
                goto start;
            }
            delete_info("wrong password");
        }
    }
    do
    {
        printf("Input key (max length %d): ", MAX_PASSWORD - 2);
    } while (fgets(key, MAX_PASSWORD, stdin) == NULL);
    key[strlen(key) - 1] = 0;
    hmac_sha256(key, strlen(key), hmac_hash, SOUTBUFF * 4 + PASSWORD_HASH_SIZE * 2, hash_password);
    for(i = 0; i < SOUTBUFF; ++i)
        sprintf(hmac_hash + i * 2, "%02x", hash_password[i]);
    if((fp = fopen(hmac_hash_place, "r")) == NULL)
    {
        if((fp = fopen(hmac_hash_place, "w")) == NULL)
            mperror("can't creat hmac hash file", CREATE_FILE_ERROR);
        i = fprintf(fp, "%s", hmac_hash);
        fclose(fp);
        if(i == -1)
            mperror("can't write in hmac hash file", WRITE_FILE_ERROR);
    }       
    else
    {
        for(i = 0; i < PASSWORD_HASH_SIZE * 2 && (c = getc(fp)) != EOF;)
            hash_password[i++] = c;
        hash_password[i] = 0;
        fclose(fp);
        if(strcmp(hmac_hash, hash_password))
        {
            if(--tries > 0)
            {
                printf("wrong key. You have %d tries.\n", tries);
                goto start;
            }
            delete_info("wrong key");
        }
    }
    for(i = 0; i < MAX_PASSWORD && password[i]; ++i)
        password[i] ^= key[i];
    for(; password[i] = key[i]; ++i)
        ;
    if((kfd = open(session_key_place, O_RDONLY | O_BINARY)) == -1 || (bfd = open(blocknote_place, O_RDONLY | O_BINARY)) == -1)
    {
        close(kfd);
        close(bfd);
        if((fp = fopen(blocknote_place, "wb")) == NULL)
            mperror("can't create blocknote file", CREATE_FILE_ERROR);
        fclose(fp);
        if((fp = fopen(session_key_place, "wb")) == NULL)
            mperror("can't create session key file", CREATE_FILE_ERROR);
        fclose(fp);
    }
    else
    {
        pbkdf2_hmac_sha256(password, strlen(password), salt, strlen(salt), 100000, PASSWORD_HASH_SIZE, hash_password);
        printf("Do you want to encrypt/decrypt(e/d): ");
        c = getchar();
        if(c == 'e')
        {
            close(kfd);
            if((fp = fopen(session_key_place, "wb")) == NULL)
                mperror("can't create session key file", CREATE_FILE_ERROR);
            for(i = 0; (n = read(bfd, bbuff, BUFSIZ)) > 0;)
                i += n;
            close(bfd);
            for(j = 0; j < i; ++j)
                if(putc((rand() % ASCII_SIZE) ^ hash_password[j % PASSWORD_HASH_SIZE], fp) == -1)
                {
                    fclose(fp);
                    mperror("can't write in session key file", WRITE_FILE_ERROR);
                }
            fclose(fp);
            if((kfd = open(session_key_place, O_RDONLY | O_BINARY)) == -1 || (bfd = open(blocknote_place, O_RDONLY | O_BINARY)) == -1)
                mperror("can't open blocknote file", OPEN_FILE_ERROR);
        }
        for(mod = i = 0; (n = read(kfd, kbuff, BUFSIZ)) > 0 && read(bfd, bbuff, BUFSIZ) > 0;)
        {
            for(j = 0; j < n; ++j, ++mod)
                bbuff[j] ^= kbuff[j] ^ hash_password[mod % PASSWORD_HASH_SIZE];
            close(bfd);
            if((bfd = open(blocknote_place, O_WRONLY | O_BINARY)) == -1)
                mperror("can't open blocknote file", OPEN_FILE_ERROR);
            lseek(bfd, i * BUFSIZ, 0);
            if(write(bfd, bbuff, n) < n)
                mperror("can't write in file", WRITE_FILE_ERROR);
            close(bfd);
            if((bfd = open(blocknote_place, O_RDONLY | O_BINARY)) == -1)
                mperror("can't open blocknote file", OPEN_FILE_ERROR);
            lseek(bfd, ++i * BUFSIZ, 0);
        }
        close(bfd);
        close(kfd);
    }
    clear_info();
}
