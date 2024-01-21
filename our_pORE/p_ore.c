#include <stdio.h>
#include <stdlib.h>
#include <pbc/pbc.h>

#include "../tool.h"
#include "../crypto.h"
#include "p_ore.h"

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
int init_ore_params(ore_pp* params, int nbits, char* param, size_t count)
{
    params->initialized = true;
    params->nbits = nbits;

    if(!count)
    {
        pbc_die("input error");
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    pairing_init_set_buf(params->pairing, param, count);

    if(pairing_is_symmetric(params->pairing))
    {
        return ERROR_PAIRING_IS_SYMMETRIC;
    }

    element_init_G1(params->g, params->pairing);
    element_random(params->g);

    return ERROR_NONE;
}

/**
 * Initialize a master secret key and a comparison key with the parameters described by params.
 * 
 * @param[out] msk              - The master secret key to initialize.
 * @param[out] ck               - The comparison key to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
*/
int init_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params)
{
    if(params == NULL)
    {
        return ERROR_NULL_POINTER;
    }
    if(!params->initialized)
    {
        return ERROR_PAIRING_NOT_INITIALIZED;
    }

    element_init_Zr(msk->s, params->pairing);
    element_init_Zr(msk->r, params->pairing);
    element_init_Zr(msk->x0, params->pairing);
    element_init_Zr(msk->x1, params->pairing);
    element_init_G1(msk->y0, params->pairing);
    element_init_G1(msk->y1, params->pairing);
    msk->initialized = true;
    
    element_init_Zr(ck->r, params->pairing);
    ck->initialized = true;

    return ERROR_NONE;
}

/**
 * Initialize a ciphertext with the parameters described by params.
 * 
 * @param[out] ctxt             - The ciphertext to initialize.
 * @param[in] params            - The parameters.
 * 
 * @return ERROR_NONE on success.
 */
int init_ore_ciphertext(ore_ciphertext* ctxt, ore_pp* params)
{
    if(ctxt == NULL || params == NULL)
    {
        return ERROR_NULL_POINTER;
    }
    if(!params->initialized)
    {
        return ERROR_PAIRING_NOT_INITIALIZED;
    }
    
    int i;

    ctxt->nbits = params->nbits;
    element_init_G1(ctxt->g0, params->pairing);
    element_init_G1(ctxt->g1, params->pairing);
    element_init_G1(ctxt->y0, params->pairing);
    element_init_G1(ctxt->y1, params->pairing);
    memset(ctxt->ct0, 0, PRF_OUTPUT_BYTES);
    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(ctxt->inter_ct[i].z0, params->pairing);
        element_init_Zr(ctxt->inter_ct[i].z1, params->pairing);
    }
    ctxt->initialized = true;

    return ERROR_NONE;
}

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
int ore_key_gen(ore_master_secret_key* msk, ore_cmp_key* ck, ore_pp* params)
{
    if(!msk->initialized)
    {
        return ERROR_MSKEY_NOT_INITIALIZED;
    }
    if(!ck->initialized)
    {
        return ERROR_QKEY_NOT_INITIALIZED;
    }

    element_random(msk->s);
    element_random(msk->r);
    element_random(msk->x0);
    element_random(msk->x1);

    element_pow_zn(msk->y0, params->g, msk->x0);
    element_pow_zn(msk->y1, params->g, msk->x1);
    element_set(ck->r, msk->r);

    return ERROR_NONE;
}

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
int ore_enc(ore_ciphertext* ctxt, ore_master_secret_key* msk, uint64_t msg, ore_pp* params)
{
    if(!ctxt->initialized)
    {
        return ERROR_CTXT_NOT_INITIALIZED;
    }
    if(!msk->initialized)
    {
        return ERROR_MSKEY_NOT_INITIALIZED;
    }

    int i;
    element_t xi, r0, r1, w, tmp;
    element_t u[PLAINTEXT_BIT*2];//u0 u1
    byte key_byte[PRF_OUTPUT_BYTES];
    byte u_byte[PRF_OUTPUT_BYTES];
    byte r_byte[PRF_OUTPUT_BYTES];
    byte u_opr_one_byte[SHA256_OUTPUT_BYTES];
    byte xi_byte[SHA256_OUTPUT_BYTES];
    byte hc_byte[SHA256_OUTPUT_BYTES];
    element_t u_opr_one;
    mpz_t mpz_u;

    int z_byte_length = element_length_in_bytes(ctxt->inter_ct[0].z0);
    byte* z0_byte = (byte *)malloc(sizeof(byte)*z_byte_length);
    memset(z0_byte, 0, z_byte_length);
    byte* z1_byte = (byte *)malloc(sizeof(byte)*z_byte_length);
    memset(z1_byte, 0, z_byte_length);
    int r_byte_length = element_length_in_bytes(msk->r);
    byte* hash2_input = (byte *)malloc(z_byte_length*(1+2*params->nbits));//r||(z0 z1)*n
    memset(hash2_input, 0, z_byte_length*(1+2*params->nbits));

    int g_byte_length = element_length_in_bytes(params->g);
    int size = g_byte_length+PRF_OUTPUT_BYTES;
    byte* hash1_input = (byte *)malloc(size*2*params->nbits);
    memset(hash1_input, 0, size*2*params->nbits);

    memset(r_byte, 0, sizeof(r_byte));
    element_to_bytes(r_byte, msk->r);
    memcpy(hash2_input, r_byte, r_byte_length);

    byte* w_byte = (byte *)malloc(sizeof(byte)*g_byte_length);
    memset(w_byte, 0, g_byte_length);

    element_init_Zr(xi, params->pairing);
    element_init_Zr(r0, params->pairing);
    element_init_Zr(r1, params->pairing);
    element_random(r0);
    element_random(r1);

    rand_permute *permute = (rand_permute *)malloc(sizeof(rand_permute)*params->nbits);
    for(i = 0; i < params->nbits; i++)
    {
        permute[i].index = i;
        permute[i].rando = rand();
    }
    qsort(permute, params->nbits, sizeof(permute), comp);

    element_pow_zn(ctxt->g1, params->g, r0);//g1^ = g_pow_r0
    element_pow_zn(ctxt->g0, params->g, r1);//g0^ = g_pow_r1
    element_pow_zn(ctxt->y1, msk->y1, r0);//y1^ = y1_pow_r0
    element_pow_zn(ctxt->y0, msk->y0, r1);//y0^ = y0_pow_r1
    element_init_G1(w, params->pairing);
    element_init_Zr(tmp, params->pairing);

    for(i = 0; i < params->nbits; i++)
    {
        element_init_Zr(u[2*i], params->pairing);//u_i0
        element_init_Zr(u[2*i+1], params->pairing);//u_i1
    }

    element_init_Zr(u_opr_one, params->pairing);
    mpz_init(mpz_u);

    memset(key_byte, 0, sizeof(key_byte));
    element_to_bytes(key_byte, msk->s);


    for(i = 0; i < params->nbits; i++)
    {
        encode(u_byte, key_byte, (byte *)&msg, sizeof(msg), permute[i].index, params->nbits);//sigma(s,m,pi(i))
        mpz_import(mpz_u, 32, 1, 1, -1, 0, u_byte);

        HMAC_SHA256(u_opr_one_byte, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES); //u_{i,0}
        element_from_bytes(u[i*2], u_opr_one_byte);
        memcpy(hash1_input+i*2*size, u_opr_one_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u_opr_one, u_opr_one_byte);
        element_pow_zn(w, ctxt->g1, u_opr_one);//Com(rnd_{i,0}) = g^(r0*u_{i,0})
        element_to_bytes(w_byte, w);
        memcpy(hash1_input+i*2*size+PRF_OUTPUT_BYTES, w_byte, g_byte_length);

        mpz_add_ui(mpz_u, mpz_u, 1); //u+1
        mpz_export(u_byte, NULL, 1, 1, -1, 0, mpz_u);
        HMAC_SHA256(u_opr_one_byte, SHA256_OUTPUT_BYTES, key_byte, u_byte, PRF_OUTPUT_BYTES); //u_{i,1}
        element_from_bytes(u[i*2+1], u_opr_one_byte);
        memcpy(hash1_input+(2*i+1)*size, u_opr_one_byte, PRF_OUTPUT_BYTES);
        element_from_bytes(u_opr_one, u_opr_one_byte);
        element_pow_zn(w, ctxt->g0, u_opr_one);
        element_to_bytes(w_byte, w);//Com(rnd_{i,1})
        memcpy(hash1_input+(2*i+1)*size+PRF_OUTPUT_BYTES, w_byte, g_byte_length);
    }

    sha_256(xi_byte, SHA256_OUTPUT_BYTES, hash1_input, size*2*params->nbits);//Hc(u||w)
    element_from_bytes(xi, xi_byte);//xi

    for(i = 0; i < params->nbits; i++)//c_{i,k} = Rsp() = st_{i,k} - sk_k*xi
    {
        element_mul(tmp, xi, msk->x0);//xi*x0
        element_mul(ctxt->inter_ct[i].z0, u[i*2], r0);//st_{i,0} = r0*u_{i,0} = rnd_{i,0}
        element_sub(ctxt->inter_ct[i].z0, ctxt->inter_ct[i].z0, tmp);//z_{i,0} = r0*u_{i,0} - xi*x0
        element_to_bytes(z0_byte, ctxt->inter_ct[i].z0);
        memcpy(hash2_input+r_byte_length+i*2*z_byte_length, z0_byte, z_byte_length);

        element_mul(tmp, xi, msk->x1);
        element_mul(ctxt->inter_ct[i].z1, u[i*2+1], r1);
        element_sub(ctxt->inter_ct[i].z1, ctxt->inter_ct[i].z1, tmp);//z_{i,1} = r1*u_{i,1} - xi*x1
        element_to_bytes(z1_byte, ctxt->inter_ct[i].z1);
        memcpy(hash2_input+r_byte_length+(2*i+1)*z_byte_length, z1_byte, z_byte_length);
    }

    sha_256(hc_byte, SHA256_OUTPUT_BYTES, hash2_input, r_byte_length + z_byte_length*2*params->nbits);//Hc(k||c1||...||cn)
    for (i = 0; i < SHA256_OUTPUT_BYTES; i++) {
			ctxt->ct0[i] = xi_byte[i] ^ hc_byte[i];//c0 = xi^Hc(k||c1||...||cn)
	}
    
    element_clear(xi);
    element_clear(r0);
    element_clear(r1);
    element_clear(w);
    element_clear(tmp);
    for(i = 0; i < params->nbits; i++)
    {
        element_clear(u[2*i]);
        element_clear(u[2*i+1]);
    }
    element_clear(u_opr_one);
    mpz_clear(mpz_u);
    free(w_byte);
    free(z0_byte);
    free(z1_byte);
    free(permute);
    free(hash1_input);
    free(hash2_input);

    return ERROR_NONE;
}

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
int ore_cmp(int* b, ore_ciphertext* ctxt1, ore_ciphertext* ctxt2, ore_cmp_key* ck, ore_pp* params)
{
    element_t v0[params->nbits];
    element_t v1[params->nbits];
    element_t v0_prime[params->nbits];
    element_t v1_prime[params->nbits];
    element_t tmp, xi, xi_prime;
    bool break_flag = false;
    int i, j, bit;
    byte hc_byte[SHA256_OUTPUT_BYTES];
    byte hc_prime_byte[SHA256_OUTPUT_BYTES];
    byte xi_byte[SHA256_OUTPUT_BYTES];
    byte xi_prime_byte[SHA256_OUTPUT_BYTES];

    int z_byte_length = element_length_in_bytes(ctxt1->inter_ct[0].z0);
    byte* z0_byte = (byte *)malloc(sizeof(byte)*z_byte_length);
    memset(z0_byte, 0, z_byte_length);
    byte* z1_byte = (byte *)malloc(sizeof(byte)*z_byte_length);
    memset(z1_byte, 0, z_byte_length);
    int r_byte_length = element_length_in_bytes(ck->r);
    byte* hash1_input = (byte *)malloc(r_byte_length + z_byte_length*2*params->nbits);//r||(z0 z1)*n
    memset(hash1_input, 0, r_byte_length + z_byte_length*2*params->nbits);

    byte r_byte[PRF_OUTPUT_BYTES];
    memset(r_byte, 0, sizeof(r_byte));
    element_to_bytes(r_byte, ck->r);
    memcpy(hash1_input, r_byte, r_byte_length);

    //xi
    for(i = 0; i < params->nbits; i++){
        element_to_bytes(z0_byte, ctxt1->inter_ct[i].z0);
        element_to_bytes(z1_byte, ctxt1->inter_ct[i].z1);
        memcpy(hash1_input+r_byte_length+i*2*z_byte_length, z0_byte, z_byte_length);
        memcpy(hash1_input+r_byte_length+(2*i+1)*z_byte_length, z1_byte, z_byte_length);
    }

    sha_256(hc_byte, SHA256_OUTPUT_BYTES, hash1_input, r_byte_length + z_byte_length*2*params->nbits);//Hc(k||c1||...||cn)

    for (i = 0; i < SHA256_OUTPUT_BYTES; i++) {
		xi_byte[i] = ctxt1->ct0[i] ^ hc_byte[i];//xi = c0^Hc(k||c1||...||cn)
	}

    //xi'
    memset(hash1_input+r_byte_length, 0, z_byte_length*2*params->nbits);
    for(i = 0; i < params->nbits; i++){
        element_to_bytes(z0_byte, ctxt2->inter_ct[i].z0);
        element_to_bytes(z1_byte, ctxt2->inter_ct[i].z1);
        memcpy(hash1_input+r_byte_length+i*2*z_byte_length, z0_byte, z_byte_length);
        memcpy(hash1_input+r_byte_length+(2*i+1)*z_byte_length, z1_byte, z_byte_length);
    }
    sha_256(hc_prime_byte, SHA256_OUTPUT_BYTES, hash1_input, r_byte_length + z_byte_length*2*params->nbits);//Hc(k||c1||...||cn)

    for (i = 0; i < SHA256_OUTPUT_BYTES; i++) {
            xi_prime_byte[i] = ctxt2->ct0[i] ^ hc_prime_byte[i];//xi' = c0^Hc(k||c1||...||cn)
	}

    for(i = 0; i < params->nbits; i++)
    {
        element_init_G1(v0[i], params->pairing);
        element_init_G1(v1[i], params->pairing);
        element_init_G1(v0_prime[i], params->pairing);
        element_init_G1(v1_prime[i], params->pairing);
    }
    element_init_G1(tmp, params->pairing);
    element_init_Zr(xi, params->pairing);
    element_init_Zr(xi_prime, params->pairing);
    element_from_bytes(xi, xi_byte);//xi
    element_from_bytes(xi_prime, xi_prime_byte);//xi'

    for(i = 0; i < params->nbits; i++)
    {
        element_pow_zn(v0[i], ctxt2->g0, ctxt1->inter_ct[i].z0);//g0'^(z_{i,0})
        element_pow_zn(tmp, ctxt2->y0, xi);//y0'^xi
        element_mul(v0[i], v0[i], tmp);//rec_{i,0} = g0'^(z_{i,0})*y0'^xi

        element_pow_zn(v1[i], ctxt2->g1, ctxt1->inter_ct[i].z1);//g1'^(z_{i,1})
        element_pow_zn(tmp, ctxt2->y1, xi);//y1'^xi
        element_mul(v1[i], v1[i], tmp);//rec_{i,1} = g1'^(z_{i,1})*y1'^xi

        element_pow_zn(v0_prime[i], ctxt1->g0, ctxt2->inter_ct[i].z0);//g0^(z'_{i,0})
        element_pow_zn(tmp, ctxt1->y0, xi_prime);//y0^xi'
        element_mul(v0_prime[i], v0_prime[i], tmp);//rec'_{i,0}

        element_pow_zn(v1_prime[i], ctxt1->g1, ctxt2->inter_ct[i].z1);//g1^(z'_{i,1})
        element_pow_zn(tmp, ctxt1->y1, xi_prime);//y1^xi'
        element_mul(v1_prime[i], v1_prime[i], tmp);//rec'_{i,1}
    }

    for(i = 0; i < params->nbits; i++)
    {
        for(j = 0; j < params->nbits; j++)
        {
            if(element_cmp(v0[i], v1_prime[j]) == 0)//?rec_{i,0} == rec'_{j,1}
            {
                bit = 1;
                break_flag = true;
                break;
            }
            else if(element_cmp(v1[i], v0_prime[j]) == 0)//?rec_{i,1} == rec'_{j,0}
            {
                bit = -1;
                break_flag = true;
                break;
            }
            else
            {
                bit = 0;
            }
        }

        if(break_flag == true) break;
    }

    *b = bit;

    for(i = 0; i < params->nbits; i++)
    {
        element_clear(v0[i]);
        element_clear(v1[i]);
        element_clear(v0_prime[i]);
        element_clear(v1_prime[i]);
    }
    element_clear(tmp);
    element_clear(xi);
    element_clear(xi_prime);
    free(hash1_input);
    free(z0_byte);
    free(z1_byte);

    return ERROR_NONE;
}

/**
 * Clear a master secreat key and a comparison key.
 *
 * @param[in] msk               - The master secreat key to clear.
 * @param[in] ck                - The comparison key to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_key(ore_master_secret_key* msk, ore_cmp_key* ck)
{
    if(msk == NULL || ck == NULL)
    {
        return ERROR_NONE;
    }

    element_clear(msk->s);
    element_clear(msk->r);
    element_clear(msk->x0);
    element_clear(msk->x1);
    element_clear(msk->y0);
    element_clear(msk->y1);

    element_clear(ck->r);

    return ERROR_NONE;
}

/**
 * Clear a ciphertext.
 *
 * @param[in] ctxt              - The ciphertext to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_ciphertext(ore_ciphertext* ctxt)
{
    if(ctxt == NULL)
    {
        return ERROR_NONE;
    }

    int i;

    element_clear(ctxt->g0);
    element_clear(ctxt->g1);
    element_clear(ctxt->y0);
    element_clear(ctxt->y1);
    for(i = 0; i < ctxt->nbits; i++)
    {
        element_clear(ctxt->inter_ct[i].z0);
        element_clear(ctxt->inter_ct[i].z1);
    }

    return ERROR_NONE;
}

/**
 * Clear the ore params.
 *
 * @param[in] params            - The token to clear.
 *
 * @return ERROR_NONE on success
 */
int clear_ore_params(ore_pp* params)
{
    if(params == NULL)
    {
        return ERROR_NONE;
    }

    element_clear(params->g);
    pairing_clear(params->pairing);
    
    return ERROR_NONE;
}