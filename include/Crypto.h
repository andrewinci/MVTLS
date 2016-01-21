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

#include "handshakeConstants.h"

#ifndef MAKEFILE
#include "ServerClientKeyExchange.h"
#else
#include "HandshakeMessages/ServerClientKeyExchange.h"
#endif

#endif /* Crypto_h */

/*
 * Starting from premaster secret, compute master key and set it in TLS_param
 */

void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, unsigned char *seed, int seed_len, int result_len, unsigned char **result);

int verify_DH_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, DHE_server_key *server_key_ex);

int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, DHE_server_key *server_key_ex) ;


