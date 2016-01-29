//
//  Crypto.h
//  SSLXcodeProject
//
//  Created by Darka on 13/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

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

#endif /* Crypto_h */

void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result);


int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);


int sign_ECDHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);
