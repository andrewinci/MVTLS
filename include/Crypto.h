/**
 *  SSL/TLS Project
 *  \file Crypto.h
 *
 * 	PRF function and sign/verify function. 
 *	The follow functions wrap openssl library for sign, verify.
 * 
 *  \date Created on 27/12/15.
 *  \copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef Crypto_h
#define Crypto_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "TLSConstants.h"

#ifndef MAKEFILE
#include "ServerClientKeyExchange.h"
#else
#include "HandshakeMessages/ServerClientKeyExchange.h"
#endif

#endif

/**
 * Apply the PRF to a secret.
 *
 *	\param hash : the hash to use in the hmac
 *	\param secret : the secret to process
 *	\param secret_len : secrete length
 *	\param label : the label of the PRF computation
 *	\param seed : the seed for the computation
 *	\param seed_len : seed length
 *	\param result : a pointer to char, will contain the result after computation. Must point to NULL
 *	\param result_len : the desired length of pseudo random stream.
 */
void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result);

/**
 * Sign the server_key_exchange message for a DHE key exchange.
 * The function choice an arbitrary hash algorithm for the signature (except md5,sha1).
 * It take private key in ../certificates/ folder with name serverA.key wher A can be RSA, DSS.
 *
 *	\param client_random : the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random : the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex : the server key exchange message to sign.
 *	\param au : the authentication algorithm.
 */
int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

/**
 * Verify the server_key_exchange message for a DHE key exchange.
 *
 *	\param certificate : the certificate to use for verify the signature
 *	\param client_random : the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random : the random sent by the server in the server hello. Must point to 32 byte stream
  *	\param server_key_ex : the server key exchange message to verify.
 *	\param au : the authentication algorithm.
 */
int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

/**
 * Sign the server_key_exchange message for a ECDHE key exchange.
 * The function choice an arbitrary hash algorithm for the signature (except md5,sha1).
 * It take private key in ../certificates/ folder with name serverA.key wher A can be RSA, ECDSA.
 *
 *	\param client_random : the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random : the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex : the server key exchange message to sign.
 *	\param au : the authentication algorithm.
 */
int sign_ECDHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

/**
 * Verify the server_key_exchange message for a ECDHE key exchange.
 *
 *	\param certificate : the certificate to use for verify the signature
 *	\param client_random : the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random : the random sent by the server in the server hello. Must point to 32 byte stream
  *	\param server_key_ex : the server key exchange message to verify.
 *	\param au : the authentication algorithm.
 */
int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);
