# ImORE

This is the implementation of the paper "Parameter-Hiding Order-Revealing Encryption without Pairings".

## Prerequisites

Required environment

- [OpenSSL-1.1.1](https://www.openssl.org/source/)
- [GMP-6.2.0](https://gmplib.org/)
- [PBC-0.5.14](https://crypto.stanford.edu/pbc/download.html)
  
  
  ## Run the test
  
  Run the correctness check by 
  
  ```shell
  # Requires type-d parameter of PBC library as input to generate asymmetric pairing
  ./tests/test_p_ore < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
  ```
  
  Run the benchmark by
  
  ```shell
  ./tests/time_p_ore < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
  ```

## Cash et al.'s scheme

We also implemented the scheme of Cash et al. at /cash_scheme.

See the paper of Cash et al. at [Springer](https://link.springer.com/chapter/10.1007/978-3-030-03326-2_7).

Run the correctness check by 

```shell
cd cash_scheme (or li_scheme, lv_schme)
make
./tests/test_cash_ore  < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```

Run the benchmark by

```shell
./tests/time_cash_ore ( < location_of_your_pbc_library/pbc-0.5.14/param/d159.param
```
