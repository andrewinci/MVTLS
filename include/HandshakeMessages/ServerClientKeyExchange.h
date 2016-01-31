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

#ifdef MAKEFILE
#include "../TLSConstants.h"
#else
#include "TLSConstants.h"
#endif


/*
 RFC 
 named_curve
 Indicates that a named curve will be used. The use of this option is
 strongly recommended.
 */
typedef struct{
	uint16_t named_curve;

	BIGNUM *pub_key;

	uint16_t sign_hash_alg; 

	unsigned int signature_length;

	unsigned char *signature;

}ecdhe_server_key_exchange_t; // we support only named curve

typedef struct{
	BIGNUM *p;

	BIGNUM *g;

	BIGNUM *pubKey;

	// Signature and hash algorithms,  1 byte for signature alg, 1byte for hash
	uint16_t sign_hash_alg; 

	unsigned int signature_length;

	unsigned char *signature;

}dhe_server_key_exchange_t;

typedef struct{
	uint16_t key_length;

	unsigned char *key;

}client_key_exchange_t;

typedef void server_key_exchange_t;

#endif

void serialize_server_key_exchange(server_key_exchange_t *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx);

server_key_exchange_t *deserialize_server_key_exchange(unsigned char *message, uint32_t message_len, key_exchange_algorithm kx);

void print_server_key_exchange(server_key_exchange_t *server_key_exchange, key_exchange_algorithm kx);

void free_server_key_exchange(server_key_exchange_t *server_key_ex, key_exchange_algorithm kx);

void serialize_client_key_exchange(client_key_exchange_t *client_key_exchange, unsigned char **stream, uint32_t *streamLen);

client_key_exchange_t *deserialize_client_key_exchange(unsigned char *message, uint32_t message_len);

void print_client_key_exchange(client_key_exchange_t *client_key_exchange);

void free_client_key_exchange(client_key_exchange_t *client_key_exchange);
