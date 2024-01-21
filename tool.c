#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>

#include "crypto.h"
#include "tool.h"

/**
 * Compare function used in qsort().
*/
int comp(const void *p1, const void *p2)
{
    rand_permute *c = (rand_permute *)p1;
    rand_permute *d = (rand_permute *)p2;
    return ((*(rand_permute *)c).rando - (*(rand_permute *)d).rando);
}

/**
 * An encoding function E(key,m,ind) = HMAC_SHA256(key,ind||m[1],m[2],...,m[ind])+m[ind] mod 2^256.
 * 
 * @param[out] buf              - The result.
 * @param[in] key               - The secret key.
 * @param[in] msg               - The message.
 * @param[in] msg_len           - The byte length of message.
 * @param[in] ind               - The index.
*/
void encode(byte* buf, byte* key, byte* msg, int msg_len, int ind, int nbits)
{
    mpz_t SHA_to_mpz;
    mpz_t SHA_256_MAX;

    int nbytes = (nbits + 7) / 8;
    int index, offset, i, j, bit;
    byte prf_input_buf[4+nbytes];
    memset(prf_input_buf, 0, 4+nbytes);

    mpz_init(SHA_to_mpz);
    
    mpz_init(SHA_256_MAX);
    mpz_init_set_str(SHA_256_MAX, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

    // the first four bytes to save ind
    prf_input_buf[0] = (byte)(ind >> 24);
	prf_input_buf[1] = (byte)(ind >> 16);
	prf_input_buf[2] = (byte)(ind >> 8);
	prf_input_buf[3] = (byte)ind;

    index = nbytes - 1 - (ind / 8);

    if(ind % 8 == 0 && ind != 0)
    {
        for (i = 4, j = nbytes-1; j > index; i++, j--)
        {
            prf_input_buf[i] = msg[j];
        }
        bit = (msg[j] >> 7) & 0x1;
    }
    else
    {
        offset = ind - (ind / 8) * 8;
        for (i = 4, j = nbytes-1; j > index; i++, j--)
        {
            prf_input_buf[i] = msg[j];
        }
        prf_input_buf[i] = msg[j] >> (8-offset);
        bit = (msg[j] >> (7-offset)) & 0x1;
    }

    HMAC_SHA256(buf, PRF_OUTPUT_BYTES, key, prf_input_buf, 4+nbytes);

    if(bit == 1)
    {
        mpz_import(SHA_to_mpz, 32, 1, 1, -1, 0, buf);
        mpz_add_ui(SHA_to_mpz, SHA_to_mpz, 1);
        mpz_and(SHA_to_mpz, SHA_to_mpz, SHA_256_MAX);
        mpz_export(buf, NULL, 1, 1, -1, 0, SHA_to_mpz);
    }
}