#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define BUFFSIZE 64
#define MAXSIZE 8
#define MAXPART 56
#define HSIZE 8
#define KSIZE 64
#define SOUTBUFF 32
uint32_t rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << 32 - n);
}
uint8_t *sha256(const uint8_t *input, size_t len, uint8_t *output_buf)
{
    static uint32_t wbuff[BUFFSIZE];
    static uint8_t cbuff[BUFFSIZE];
    uint32_t H[HSIZE] = 
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    static uint32_t var[HSIZE];
    static uint32_t kbuff[BUFFSIZE] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    size_t size = len * 8;
    uint32_t s0, s1, ch, temp1, temp2, maj;
    int is_used_one, is_used_size, ind, temp;
    is_used_one = is_used_size = 0;
    while(len > 0 || !is_used_size)
    {
        if(len >= BUFFSIZE)
            for(ind = 0; ind < BUFFSIZE; --len)
                cbuff[ind++] = *input++;
        else if(len >= MAXPART)
        {
            for(ind = 0; len > 0; --len)
                cbuff[ind++] = *input++;
            is_used_one = 1;
            cbuff[ind++] = 0x80;
            memset(cbuff + ind, 0, (BUFFSIZE - ind) * sizeof(cbuff));
        }
        else
        {
            for(ind = 0; len > 0; --len)
                cbuff[ind++] = *input++;
            if(!is_used_one)
            {
                cbuff[ind++] = 128;
                is_used_one = 1;
            }
            memset(cbuff + ind, 0, (MAXPART - ind) * sizeof(cbuff));
            for(ind = 0; ind < 8; ++ind)
                cbuff[MAXPART + 7 - ind] = (uint8_t)(size >> (ind * 8));
            is_used_size = 1;
        }
        memset(wbuff, 0, sizeof(wbuff));
        for(ind = 0; ind < BUFFSIZE; ++ind)
            wbuff[ind / 4] |= ((uint32_t)(cbuff[ind])) << ((3 - (ind % 4)) * 8);
        for(ind = 16; ind < BUFFSIZE; ++ind)
        {
            s0 = rotr(wbuff[ind - 15], 7) ^ rotr(wbuff[ind - 15], 18) ^ (wbuff[ind - 15] >> 3);
            s1 = rotr(wbuff[ind - 2], 17) ^ rotr(wbuff[ind - 2], 19) ^ (wbuff[ind - 2] >> 10);
            wbuff[ind] = wbuff[ind - 16] + s0 + wbuff[ind - 7] + s1;
        }
        memcpy(var, H, sizeof(H));
        for(ind = 0; ind < BUFFSIZE; ++ind)
        {
            s0 = rotr(var[0], 2) ^ rotr(var[0], 13) ^ rotr(var[0], 22);
            s1 = rotr(var[4], 6) ^ rotr(var[4], 11) ^ rotr(var[4], 25);
            ch = (var[4] & var[5]) ^ ((~var[4]) & var[6]);
            temp1 = var[7] + s1 + ch + kbuff[ind] + wbuff[ind];
            maj = (var[0] & var[1]) ^ (var[0] & var[2]) ^ (var[1] & var[2]);
            temp2 = s0 + maj;
            for(temp = 7; temp >= 0; --temp)
            {
                if(temp == 4)
                    var[temp] = var[temp - 1] + temp1;
                else if(temp == 0)
                    var[temp] = temp1 + temp2;
                else
                    var[temp] = var[temp - 1];
            }
        }
        for(ind = 0; ind < HSIZE; ++ind)
            H[ind] += var[ind];
    }
    for(ind = 0; ind < HSIZE; ++ind)
    {
        output_buf[ind * 4 + 3] = H[ind] & 0xFF;
        output_buf[ind * 4 + 2] = (H[ind] >> 8) & 0xFF;
        output_buf[ind * 4 + 1] = (H[ind] >> 16) & 0xFF;
        output_buf[ind * 4] = (H[ind] >> 24) & 0xFF;
    }
    return output_buf;
}
uint8_t *hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *message, size_t msg_len, uint8_t *output_buf)
{
    uint8_t K0[BUFFSIZE], ipad[BUFFSIZE], opad[BUFFSIZE], inner_hash[SOUTBUFF];
    uint8_t *buff;
    int i;
    if(key_len == BUFFSIZE)
        memcpy(K0, key, BUFFSIZE);
    else if(key_len > BUFFSIZE)
    {
        sha256(key, key_len, K0);
        memset(K0 + SOUTBUFF, 0, BUFFSIZE - SOUTBUFF);
    }
    else
    {
        memcpy(K0, key, key_len);
        memset(K0 + key_len, 0, BUFFSIZE - key_len);
    }
    for(i = 0; i < BUFFSIZE; ++i)
    {
        ipad[i] = K0[i] ^ 0x36;
        opad[i] = K0[i] ^ 0x5c;
    }
    buff = malloc(BUFFSIZE + msg_len);
    memcpy(buff, ipad, BUFFSIZE);
    memcpy(buff + BUFFSIZE, message, msg_len);
    sha256(buff, BUFFSIZE + msg_len, inner_hash);
    free(buff);
    buff = malloc(BUFFSIZE + SOUTBUFF);
    memcpy(buff, opad, BUFFSIZE);
    memcpy(buff + BUFFSIZE, inner_hash, SOUTBUFF);
    sha256(buff, BUFFSIZE + SOUTBUFF, output_buf);
    return output_buf;
}
uint8_t *pbkdf2_hmac_sha256(const uint8_t *message, size_t msg_len, const uint8_t *salt, size_t slt_size, size_t c, size_t dklen, uint8_t *dk)
{
    uint8_t Un[SOUTBUFF], Ub[SOUTBUFF], Ur[SOUTBUFF];
    uint8_t *str;
    uint32_t l, r, size, j, m, offset;
    uint32_t i;
    l = (dklen - 1) / SOUTBUFF + 1;
    r = dklen - (l - 1) * SOUTBUFF;
    str = malloc(size = slt_size + 4);
    memcpy(str, salt, slt_size);
    for(i = 1; i <= l; ++i)
    {
        for(j = 0; j < 4; ++j)
            str[slt_size + j] = (uint8_t)(i >> ((3 - j) * 8));
        hmac_sha256(message, msg_len, str, size, Ub);
        memcpy(Ur, Ub, SOUTBUFF);
        for(j = 1; j < c; ++j)
        {
            hmac_sha256(message, msg_len, Ub, SOUTBUFF, Un);
            for(m = 0; m < SOUTBUFF; ++m)
                Ur[m] ^= Un[m];
            memcpy(Ub, Un, SOUTBUFF);
        }
        memcpy(dk + (i - 1) * SOUTBUFF, Ur, (i == l) ? r : SOUTBUFF);
    }
    free(str);
    return dk;
}

