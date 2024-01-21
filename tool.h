#ifndef __TOOL_H__
#define __TOOL_H__

#include "crypto.h"

typedef struct {
    uint32_t index;
    uint32_t rando;
} rand_permute;

/**
 * Compare function used in qsort().
*/
int comp(const void *p1, const void *p2);

/**
 * An encoding function E(key,m,ind) = HMAC_SHA256(key,ind||m[1],m[2],...,m[ind])+m[ind] mod 2^256.
 * 
 * @param[out] buf              - The result.
 * @param[in] key               - The secret key.
 * @param[in] msg               - The message.
 * @param[in] msg_len           - The byte length of message.
 * @param[in] ind               - The index.
*/
void encode(byte* buf, byte* key, byte* msg, int msg_len, int ind, int nbits);

#endif /* __TOOL_H__ */