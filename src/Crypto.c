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

/**
 * Use the private key ../certificates/serverDSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeded, -1 if an error occurred
 */
int sign_with_DSS(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type){
	// Get private key for sign
	FILE *private_key_file = fopen("../certificates/serverDSA.key", "r");
	if (!private_key_file) {
		fprintf(stderr, "Unable to open DSA private key file, store it in ../certificates/serverDSA.key\n");
		exit(-1);
	}

	DSA *dsa_private = PEM_read_DSAPrivateKey(private_key_file, NULL, NULL, NULL);
	fclose(private_key_file);

	// Allocate memory for signature
	*signature = malloc(sizeof(unsigned char)*DSA_size(dsa_private));

	int res = DSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, dsa_private );

	DSA_free(dsa_private);

	return res;
}

/**
 * Use the private key ../certificates/serverRSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeded, -1 if an error occurred
 */
int sign_with_RSA(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type) {
	// Get private key from file
	int res;
	RSA *rsa_private = NULL;
	FILE *fp;

	if((fp= fopen("../certificates/serverRSA.key", "r")) != NULL){
		rsa_private=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
		if(rsa_private==NULL){
			printf("\nUnable to open RSA private key, store it in ../certificates/serverRSA.key\n");
			exit(-1);
		}
	}
	fclose(fp);

	// Allocate memory for signature
	*signature = malloc(sizeof(unsigned char)*RSA_size(rsa_private));

	res = RSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, rsa_private);

	RSA_free(rsa_private);

	return res;
}

/**
 * Use the private key ../certificates/serverECDSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeced, -1 if an error occurred
 */
int sign_with_ECDSA(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type){
	int res;
	EC_KEY *ecdsa_private;
	// Get private key for sign
	FILE *private_key_file = fopen("../certificates/serverECDSA.key", "r");
	if (!private_key_file) {
		fprintf(stderr, "\nUnable to open ECDSA private key file, store it in ../certificates/serverECDSA.key\n");
		exit(-1);
	}

	ecdsa_private = PEM_read_ECPrivateKey(private_key_file, NULL, NULL, NULL);

	fclose(private_key_file);

	// Allocate memory for signature
	*signature = malloc(sizeof(unsigned char)*ECDSA_size(ecdsa_private));

	res = ECDSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, ecdsa_private );

	EC_KEY_free(ecdsa_private);

	return res;
}

/**
 * Sign the server_key_exchange message for a DHE key exchange.
 * The function chooses an arbitrary hash algorithm for the signature (except MD5, SHA-1).
 * It takes private key in ../certificates/ folder with name serverA.key where A can be RSA, DSS.
 *
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to sign.
 *	\param au: the authentication algorithm.
 */
int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au) {

	// Extract p, g, pubkey
	int p_len;
	unsigned char *p = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->p));
	p_len = BN_bn2bin(server_key_ex->p, p);

	int g_len;
	unsigned char *g = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->g));
	g_len = BN_bn2bin(server_key_ex->g, g);

	int pubkey_len;
	unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pubKey));
	pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey_char);

	// Choose random hash alg
	srand((int)time(NULL));
	hash_algorithm sign_hash_alg = rand()%4+3;
	server_key_ex->sign_hash_alg = sign_hash_alg+(au<<8);

	int sign_type;
	const EVP_MD *hash;
	switch (sign_hash_alg) {
		case SHA224_H:
			sign_type = NID_sha224;
			hash = EVP_sha224();
			break;
		case SHA256_H:
			sign_type = NID_sha256;
			hash = EVP_sha256();
			break;
		case SHA384_H:
			sign_type = NID_sha384;
			hash = EVP_sha384();
			break;
		case SHA512_H:
			sign_type = NID_sha512;
			hash = EVP_sha512();
			break;
		default:
			printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
			exit(-1);
	}

	// Compute hash
	unsigned char hash_digest[hash->md_size];

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash, NULL);
	EVP_DigestUpdate(mdctx, client_random, 32);
	EVP_DigestUpdate(mdctx, server_random, 32);
	EVP_DigestUpdate(mdctx, p, p_len);
	EVP_DigestUpdate(mdctx, g, g_len);
	EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
	EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
	EVP_MD_CTX_destroy(mdctx);

	int result = 0;

	switch (au) {
		case RSA_AU:
			result = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
			break;
		case DSS_AU:
			result = sign_with_DSS(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
			break;
		default:
			printf("\nError in sign_DHE_server_key_ex\n");
			exit(-1);
	}

	free(p);
	free(g);
	free(pubkey_char);

	return result;
}

/**
 * Verify the server_key_exchange message for a DHE key exchange.
 *
 *	\param certificate: the certificate to use to verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au) {

	// Extract p, g, pubkey
	int p_len;
	unsigned char *p = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->p));
	p_len = BN_bn2bin(server_key_ex->p, p);

	int g_len;
	unsigned char *g = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->g));
	g_len = BN_bn2bin(server_key_ex->g, g);

	int pubkey_len;
	unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pubKey));
	pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey_char);

	// Get hash function from packet
	hash_algorithm sign_hash_alg = (server_key_ex->sign_hash_alg) & 0x00FF;

	int sign_type;
	const EVP_MD *hash;
	switch (sign_hash_alg) {
		case SHA224_H:
			sign_type = NID_sha224;
			hash = EVP_sha224();
			break;
		case SHA256_H:
			sign_type = NID_sha256;
			hash = EVP_sha256();
			break;
		case SHA384_H:
			sign_type = NID_sha384;
			hash = EVP_sha384();
			break;
		case SHA512_H:
			sign_type = NID_sha512;
			hash = EVP_sha512();
			break;
		default:
			printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
			exit(-1);
	}

	// Compute hash
	unsigned char hash_digest[hash->md_size];

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash, NULL);
	EVP_DigestUpdate(mdctx, client_random, 32);
	EVP_DigestUpdate(mdctx, server_random, 32);
	EVP_DigestUpdate(mdctx, p, p_len);
	EVP_DigestUpdate(mdctx, g, g_len);
	EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
	EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
	EVP_MD_CTX_destroy(mdctx);

	int result = 0;
	if(au == RSA_AU){
		EVP_PKEY *pubkey = NULL;
		RSA *rsa = NULL;
		pubkey = X509_get_pubkey(certificate);
		rsa = EVP_PKEY_get1_RSA(pubkey);
		result = RSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, rsa);
		EVP_PKEY_free(pubkey);
		RSA_free(rsa);
	}
	else if(au == DSS_AU){
		EVP_PKEY *pubkey = NULL;
		DSA *dsa = NULL;
		pubkey = X509_get_pubkey(certificate);
		dsa = EVP_PKEY_get1_DSA(pubkey);
		result = DSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, dsa);
		EVP_PKEY_free(pubkey);
		DSA_free(dsa);
	}

	// Clean up
	free(p);
	free(g);
	free(pubkey_char);

	return result;
}

/**
 * Sign the server_key_exchange message for a ECDHE key exchange.
 * The function chooses an arbitrary hash algorithm for the signature (except MD5, SHA-1).
 * It takes private key in ../certificates/ folder with name serverA.key where A can be RSA, ECDSA.
 *
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to sign.
 *	\param au: the authentication algorithm.
 */
int sign_ECDHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au){

	// RFC 4492
	int pubkey_len;
	unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pub_key));
	pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);

	// Choose random hash alg
	srand((int)time(NULL));
	hash_algorithm sign_hash_alg = rand()%4+3;
	server_key_ex->sign_hash_alg = sign_hash_alg+(au<<8);

	int sign_type;
	const EVP_MD *hash;
	switch (sign_hash_alg) {
		case SHA224_H:
			sign_type = NID_sha224;
			hash = EVP_sha224();
			break;
		case SHA256_H:
			sign_type = NID_sha256;
			hash = EVP_sha256();
			break;
		case SHA384_H:
			sign_type = NID_sha384;
			hash = EVP_sha384();
			break;
		case SHA512_H:
			sign_type = NID_sha512;
			hash = EVP_sha512();
			break;
		default:
			printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
			exit(-1);
	}

	// Compute hash
	unsigned char hash_digest[hash->md_size];

	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash, NULL);
	EVP_DigestUpdate(mdctx, client_random, 32);
	EVP_DigestUpdate(mdctx, server_random, 32);
	EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
	EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
	EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
	EVP_MD_CTX_destroy(mdctx);

	int res=0;
	switch (au) {
		case RSA_AU:
			res = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
			break;
		case ECDSA_AU:
			res = sign_with_ECDSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
		default:
			break;
	}

	free(pubkey_char);

	return res;
}

/**
 * Verify the server_key_exchange message for a ECDHE key exchange.
 *
 *	\param certificate: the certificate to use for verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au){

	int pubkey_len;
	unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pub_key));
	pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);
	
	// Get hash function from packet
	hash_algorithm sign_hash_alg = (server_key_ex->sign_hash_alg) & 0x00FF;
	int sign_type;
	const EVP_MD *hash;
	switch (sign_hash_alg) {
		case SHA224_H:
			sign_type = NID_sha224;
			hash = EVP_sha224();
			break;
		case SHA256_H:
			sign_type = NID_sha256;
			hash = EVP_sha256();
			break;
		case SHA384_H:
			sign_type = NID_sha384;
			hash = EVP_sha384();
			break;
		case SHA512_H:
			sign_type = NID_sha512;
			hash = EVP_sha512();
			break;
		default:
			printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
			exit(-1);
	}

	// Compute hash
	unsigned char hash_digest[hash->md_size];
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash, NULL);
	EVP_DigestUpdate(mdctx, client_random, 32);
	EVP_DigestUpdate(mdctx, server_random, 32);
	EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
	EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
	EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
	EVP_MD_CTX_destroy(mdctx);

	int result = 0;
	if(au == RSA_AU){
		EVP_PKEY *pubkey = NULL;
		RSA *rsa = NULL;
		pubkey = X509_get_pubkey(certificate);
		rsa = EVP_PKEY_get1_RSA(pubkey);
		result = RSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, rsa);
		EVP_PKEY_free(pubkey);
		RSA_free(rsa);
	}
	else if(au == ECDSA_AU){
		EVP_PKEY *pubkey = NULL;
		EC_KEY *ecdsa = NULL;
		pubkey = X509_get_pubkey(certificate);
		ecdsa = EVP_PKEY_get1_EC_KEY(pubkey);
		result = ECDSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, ecdsa);
		EVP_PKEY_free(pubkey);
		EC_KEY_free(ecdsa);
	}

	free(pubkey_char);

	return result;
}
