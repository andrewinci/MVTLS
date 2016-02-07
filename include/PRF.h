/**
 *	SSL/TLS Project
 *	\file PRF.c
 *
 * 	PRF function.
 *
 *	\date Created on 27/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef Crypto_h
#define Crypto_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>

#endif

/**
 * Apply the PRF to a secret.
 *
 *	\param hash: the hash to use in the hmac
 *	\param secret: the secret to process
 *	\param secret_len: secrete length
 *	\param label: the label of the PRF computation
 *	\param seed: the seed for the computation
 *	\param seed_len: seed length
 *	\param result: a pointer to char, will contain the result after computation. Must point to NULL
 *	\param result_len: the desired length of pseudo random stream.
 */
void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result);
