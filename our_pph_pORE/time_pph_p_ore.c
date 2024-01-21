#include <stdio.h>
#include <time.h>

#include "p_ore.h"
#include "errors.h"

//./tests/time_p_ore < ../library/pbc-0.5.14/param/d159.param
static int _err;
#define ERR_CHECK(x)            \
    if ((_err = x) != ERROR_NONE) \
    {                             \
    return _err;                \
    }

int main(int argc, char **argv)
{
    const uint32_t NBITS[] = {8, 16, 24, 32, 48, 64};

    const int N_ENC_TRIALS = 100;
    const int N_CMP_TRIALS = 100;

    uint32_t nbits_len = sizeof(NBITS) / sizeof(int);

    printf("n = bit length of plaintext space\n\n");
    printf("%2s %12s %15s %15s %12s %16s %16s %18s\n", "n", "enc iter", "enc avg (ms)", "enc total (s)", "cmp iter", "cmp avg (ms)", "cmp total (s)", "ctxt_len (bytes)");

    ore_pp params;
    ore_master_secret_key msk;
    ore_cmp_key ck;
    ore_ciphertext ctxt1, ctxt2;

    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);

    uint64_t byte_len_of_ctxt = 0;

    uint64_t mask, msg1, msg2;

    for(int i = 0; i < nbits_len; i++)
    {
        ERR_CHECK(init_ore_params(&params, NBITS[i], param, count));
        ERR_CHECK(init_ore_key(&msk, &ck, &params));
        ERR_CHECK(init_ore_ciphertext(&ctxt1, &params));
        ERR_CHECK(init_ore_ciphertext(&ctxt2, &params));

        ERR_CHECK(ore_key_gen(&msk, &ck, &params));

        mask = (NBITS[i] == 64) ? 0xffffffff : (uint64_t)(1 << NBITS[i]) - 1;

        //time test for ore_enc
        clock_t start_time = clock();
        int enc_trials = N_ENC_TRIALS / (i + 1);
        for(int j = 0; j < enc_trials; j++)
        {
            if(NBITS[i] == 64)
            {
                msg1 = rand() & mask;
                msg1 <<= 32;
                msg1 += rand() & mask;
            }
            else
            {
                msg1 = rand() & mask;
            }
            ERR_CHECK(ore_enc(&ctxt1, &msk, msg1, &params));
        }
        double enc_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double enc_time = enc_time_elapsed / enc_trials * 1000;
        byte_len_of_ctxt = element_length_in_bytes(ctxt1.g0[0])*4*NBITS[i] + PRF_OUTPUT_BYTES*NBITS[i] + element_length_in_bytes(ctxt1.inter_ct[0].z0)*NBITS[i]*2;

        if(NBITS[i] == 64)
        {
            msg2 = rand() & mask;
            msg2 <<= 32;
            msg2 += rand() & mask;
        }
        else
        {
            msg2 = rand() & mask;
        }
        ERR_CHECK(ore_enc(&ctxt2, &msk, msg2, &params));

        //time_test for ore_cmp
        int res;

        start_time = clock();
        for(int j = 0; j < N_CMP_TRIALS; j++)
        {
            ore_cmp(&res, &ctxt1, &ctxt2, &ck, &params);
        }
        double cmp_time_elapsed = (double)(clock() - start_time) / CLOCKS_PER_SEC;
        double cmp_time = cmp_time_elapsed / N_CMP_TRIALS * 1000;

        printf("%2d %12d %15.2f %15.2f %12d %16.2f %16.2f %18lu\n",
           NBITS[i], enc_trials, enc_time, enc_time_elapsed, N_CMP_TRIALS, cmp_time,
           cmp_time_elapsed, byte_len_of_ctxt);

        ERR_CHECK(clear_ore_key(&msk, &ck));
        ERR_CHECK(clear_ore_ciphertext(&ctxt1));
        ERR_CHECK(clear_ore_ciphertext(&ctxt2));
    }

    ERR_CHECK(clear_ore_params(&params));

    return 0;
}