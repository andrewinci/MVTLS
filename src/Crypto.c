/**
 *	SSL/TLS Project
 *	\file Crypto.c
 *
 * 	PRF function and sign/verify function. 
 *	The follow functions wrap openssl library for sign, verify.
 * 
 *	\date Created on 27/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#include "Crypto.h"

/**
 * Apply the PRF to a secret.
 *
 *	\param hash: the hash to use in the hmac
 *	\param secret: the secret to process
 *	\param secret_len: secret length
 *	\param label: the label of the PRF computation
 *	\param seed: the seed for the computation
 *	\param seed_len: seed length
 *	\param result: a pointer to char, will contain the result after computation. Must point to NULL
 *	\param result_len: the desired length of pseudo random stream.
 */
void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result){
	int buffer_size = ((1+result_len/hash->md_size)*hash->md_size);
	unsigned char *buff = malloc(sizeof(unsigned char)*buffer_size);
	int label_len = (int)strlen(label);
	*result = buff;

	// Compute p_hash(secret,seed)
	// secret is equal to secret
	// seed is equal to label concatenate with seed
	unsigned char *seed_p = malloc(sizeof(unsigned char)*(label_len+seed_len));
	memcpy(seed_p, label, label_len);
	memcpy(seed_p+label_len, seed, seed_len);

	// Compute A_i
	int tot_len = 0;
	unsigned int a_len = label_len+seed_len;
	unsigned char *a = seed_p;
	while (tot_len<result_len){
		unsigned char *temp = NULL;
		temp = HMAC(hash, secret, secret_len, a, a_len, NULL, &a_len);
		a = temp;
		memcpy(buff+tot_len, a, a_len);
		tot_len+=a_len;
	}
	free(seed_p);
}