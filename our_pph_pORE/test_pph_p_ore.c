#include <stdint.h>
#include <stdio.h>

#include "p_ore.h"
#include "../errors.h"

#define ERR_CHECK(x) if((err = x) != ERROR_NONE) { return err; }

//./tests/test_pph_p_ore < ../library/pbc-0.5.14/param/d159.param
static int check_ore(ore_pp* params, int err, char* param, size_t count)
{
    int nbits = 32; // You can choose 16, 32, 64 etc. MAX nbits = 64.
    uint64_t mask = (nbits == 64) ? 0xffffffff : (uint64_t)(1 << nbits) - 1;

    uint64_t n1, n2;

    if(nbits == 64)
    {
        n1 = rand() & mask;
        n1 <<= 32;
        n1 += rand() & mask;
        n2 = rand() & mask;
        n2 <<= 32;
        n2 += rand() & mask;
    }
    else
    {
        n1 = rand() & mask;
        n2 = rand() & mask;
    }

    int cmp = (n1 < n2) ? -1 : 1;
    if (n1 == n2) cmp = 0;

    ERR_CHECK(init_ore_params(params, nbits, param, count));

    ore_master_secret_key msk;
    ore_cmp_key ck;
    ERR_CHECK(init_ore_key(&msk, &ck, params));
    ERR_CHECK(ore_key_gen(&msk, &ck, params));
    
    ore_ciphertext ctxt1, ctxt2;
    ERR_CHECK(init_ore_ciphertext(&ctxt1, params));
    ERR_CHECK(init_ore_ciphertext(&ctxt2, params));

    ERR_CHECK(ore_enc(&ctxt1, &msk, n1, params));
    ERR_CHECK(ore_enc(&ctxt2, &msk, n2, params));

    int ret = 0;
    int res;
    ERR_CHECK(ore_cmp(&res, &ctxt1, &ctxt2, &ck, params));
    if (res == cmp) {
        ret = 0;  // success
    }
    else {
        ret = -1; // fail
    }

    ERR_CHECK(clear_ore_key(&msk, &ck));
    ERR_CHECK(clear_ore_ciphertext(&ctxt1));
    ERR_CHECK(clear_ore_ciphertext(&ctxt2));

    return ret;
}

int main(int argc, char **argv)
{
    srand((unsigned)time(NULL));

    printf("Testing ORE...\n");

    fflush(stdout);

    int err = 0;
    ore_pp params;

    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);

    int test_round = 10;
    for (int i = 0; i < test_round; i++) {
        printf("round %d\n", i + 1);

        if (check_ore(&params, err, param, count) != ERROR_NONE) {
            printf("FAIL\n");
            return -1;
        }
    }

    printf("PASS\n");
    
    ERR_CHECK(clear_ore_params(&params));

    return 0;
}