//
//  SSL/TLS Project
//  ServerClientKeyExchange.h
//
//  Created on 06/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifndef ServerClientKeyExchange_h
#define ServerClientKeyExchange_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#endif

#ifdef MAKEFILE
#include "../handshakeConstants.h"
#else
#include "handshakeConstants.h"
#endif

void serialize_key_exchange(uint32_t key_length, unsigned char *encrypted_premaster_key, unsigned char **stream, uint32_t *len, key_exchange_algorithm kx);

void deserialize_key_exchange(uint32_t message_len, unsigned char *message, unsigned char **encrypted_premaster_key, uint32_t *key_len, key_exchange_algorithm kx);

void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, int label_len, unsigned char *seed, int seed_len, int result_len, unsigned char **result);
