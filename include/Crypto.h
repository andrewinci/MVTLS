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

//int verify_signature( unsigned char *message, int message_len, unsigned char *signature, int signature_len, TLS_parameters *parameters);

int sign_DH_server_key_ex(unsigned char *client_random, unsigned char *server_random, DH_server_key_exchange *server_key_ex) ;


