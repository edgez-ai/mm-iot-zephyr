/*
 * Copyright (c) 2026 EdgeZeron AI AB. All rights reserved.
 * Licensed under the EdgeZ Commercial Software License.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>

typedef long os_time_t;

struct os_time {
    os_time_t sec;
    os_time_t usec;
};

struct os_reltime {
    os_time_t sec;
    os_time_t usec;
};

int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx, int mode, size_t length,
                          unsigned char iv[16], const unsigned char *input,
                          unsigned char *output)
{
    unsigned char block[16];

    if ((length & 0x0fU) != 0U)
    {
        return MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH;
    }

    while (length != 0U)
    {
        if (mode == MBEDTLS_AES_ENCRYPT)
        {
            for (size_t i = 0; i < sizeof(block); ++i)
            {
                block[i] = input[i] ^ iv[i];
            }
            int ret = mbedtls_aes_crypt_ecb(ctx, mode, block, output);
            if (ret != 0)
            {
                return ret;
            }
            memcpy(iv, output, sizeof(block));
        }
        else
        {
            memcpy(block, input, sizeof(block));
            int ret = mbedtls_aes_crypt_ecb(ctx, mode, input, output);
            if (ret != 0)
            {
                return ret;
            }
            for (size_t i = 0; i < sizeof(block); ++i)
            {
                output[i] ^= iv[i];
            }
            memcpy(iv, block, sizeof(block));
        }
        input += sizeof(block);
        output += sizeof(block);
        length -= sizeof(block);
    }
    return 0;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen)
{
    (void)data;
    if (output == NULL || olen == NULL || sys_csrand_get(output, len) != 0)
    {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    *olen = len;
    return 0;
}

void os_sleep(os_time_t sec, os_time_t usec)
{
    int64_t milliseconds = (int64_t)sec * 1000LL +
                           ((int64_t)usec + 999LL) / 1000LL;
    if (milliseconds > 0)
    {
        k_msleep(milliseconds);
    }
}

static void edgez_hostap_set_time(os_time_t *sec, os_time_t *usec)
{
    int64_t now_us = k_ticks_to_us_floor64(k_uptime_ticks());
    *sec = (os_time_t)(now_us / 1000000LL);
    *usec = (os_time_t)(now_us % 1000000LL);
}

int os_get_time(struct os_time *t)
{
    if (t == NULL)
    {
        return -1;
    }
    edgez_hostap_set_time(&t->sec, &t->usec);
    return 0;
}

int os_get_reltime(struct os_reltime *t)
{
    if (t == NULL)
    {
        return -1;
    }
    edgez_hostap_set_time(&t->sec, &t->usec);
    return 0;
}

int os_get_random(unsigned char *buf, size_t len)
{
    return buf != NULL && sys_csrand_get(buf, len) == 0 ? 0 : -1;
}

unsigned long os_random(void)
{
    return (unsigned long)sys_rand32_get();
}

void *os_zalloc(size_t size)
{
    return calloc(1U, size);
}

int os_memcmp_const(const void *a, const void *b, size_t len)
{
    const unsigned char *left = a;
    const unsigned char *right = b;
    unsigned char difference = 0U;

    for (size_t i = 0; i < len; ++i)
    {
        difference |= left[i] ^ right[i];
    }
    return difference;
}

void *os_memdup(const void *src, size_t len)
{
    void *copy = malloc(len);
    if (copy != NULL)
    {
        memcpy(copy, src, len);
    }
    return copy;
}

size_t os_strlcpy(char *dest, const char *src, size_t size)
{
    size_t source_length = strlen(src);
    if (size != 0U)
    {
        size_t copy_length = source_length < size - 1U ?
                             source_length : size - 1U;
        memcpy(dest, src, copy_length);
        dest[copy_length] = '\0';
    }
    return source_length;
}
