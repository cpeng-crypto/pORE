#ifndef __P_ORE_H__
#define __P_ORE_H__

#include <pbc/pbc.h>
#include <stdbool.h>

#include "../crypto.h"
#include "../errors.h"

static const int PLAINTEXT_BIT = 64;

/* system parameters */
typedef struct {
    bool initialized;
    int nbits;
    element_t g;
    pairing_t pairing;
} ore_pp;

/* master secret key */
typedef struct {
    bool initialized;
    element_t s;
    element_t r;
    element_t x0;
    element_t x1;
    element_t y0;//g^x0
    element_t y1;//g^x1
} ore_master_secret_key;

/* comparison key */
typedef struct {
    bool initialized;
    element_t r;
} ore_cmp_key;

typedef struct {
    element_t z0;
    element_t z1;
} ore_inter_ctxt;

/* ciphertext */
typedef struct {
    bool initialized;
    int nbits;
    element_t g0[PLAINTEXT_BIT];
    element_t g1[PLAINTEXT_BIT];
    element_t y0[PLAINTEXT_BIT];
    element_t y1[PLAINTEXT_BIT];
    byte ct0[PLAINTEXT_BIT][PRF_OUTPUT_BYTES];
    ore_inter_ctxt inter_ct[PLAINTEXT_BIT];
} ore_ciphertext;

/**
 * Initialize an ore_pp type by setting its parameters, number of bits.
 * 
 * @param[out] params           - The params to initialize.
 * @param[in] nbits             - The number of bits of an input to the encryption scheme.
 * @param[in] param             - The param information.
 * @param[in] count             - The size of param.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_params(ore_pp* params, int nbits, char* param, size_t count);

/**
 * Initialize a master secret key and a comparison key with the parameters described by params.
 * 
 * @param[out] msk              - The master secret key to initialize.
 * @param[out] ck               - The comparison key to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params);

/**
 * Initialize a ciphertext with the parameters described by params.
 * 
 * @param[out] ctxt             - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_ciphertext(ore_ciphertext* ctxt, ore_pp* params);

/**
 * The key generation algorithm.
 * 
 * The master secret key and comparison key must be initialized (by a call to init_ore_key) before calling this function.
 * 
 * @param[out] msk              - The generated master secret key.
 * @param[out] ck               - The generated comparison key.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_key_gen(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params);

/**
 * The encryption algorithm.
 * 
 * The ciphertext must be initialized (by a call to init_ore_ciphertext) before calling this function.
 * 
 * @param[out] ctxt             - The ciphertext to store the encrypt result.
 * @param[in] msk               - The master secret key.
 * @param[in] msg               - The plaintext in uint64_t format.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_enc(ore_ciphertext* ctxt, ore_master_secret_key* msk, uint64_t msg, ore_pp* params);

/**
 * The comparison algorithm.
 * 
 * Both ciphertext and comparison key must be initialized before calling this function.
 * 
 * @param[out] b                - A flag bit.
 * @param[in] ctxt1             - The first ciphertext.
 * @param[in] ctxt2             - The second ciphertext.
 * @param[in] ck                - The comparison key.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int ore_cmp(int* b, ore_ciphertext* ctxt1, ore_ciphertext* ctxt2, ore_cmp_key* ck, ore_pp* params);

/**
 * Clear a master secreat key and a comparison key.
 *
 * @param[in] msk               - The master secreat key to clear.
 * @param[in] ck                - The comparison key to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck);

/**
 * Clear a ciphertext.
 *
 * @param[in] ctxt              - The ciphertext to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext* ctxt);

/**
 * Clear the ore params.
 *
 * @param[in] params            - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_params(ore_pp* params);

#endif /* __P_ORE_H__ */