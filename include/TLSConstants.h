//
//  SSL/TLS Project
//  TLSConstants.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
// This file contains a set of constants used in 
// the handshake protocol and some function 
//

#ifndef TLSConstants_h
#define TLSConstants_h
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/hmac.h>

#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})
#define REV32(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})

/*
 * Record Version
 */
typedef enum{
	SSL3_0 = 0x0300,
	TLS1_0 = 0x0301,
	TLS1_1 = 0x0302,
	TLS1_2 = 0x0303
}TLS_version;

typedef enum{
	NONE_KX = -1,
	RSA_KX = 1,
	DHE_KX = 2,
	ECDHE_KX = 3
}key_exchange_algorithm;

typedef enum{
	NONE_AU = -1,
	RSA_AU = 1,
	DSS_AU = 2,
	ECDSA_AU = 3
}authentication_algorithm;

typedef enum{
	NONE_H = 0,
	MD5_H = 1,
	SHA1_H = 2,
	SHA224_H = 3,
	SHA256_H = 4,
	SHA384_H = 5,
	SHA512_H = 6
}hash_algorithm;

typedef enum{
	SERVER_MODE,
	CLIENT_MODE
}channel_mode;

/*
 * Types of handshake packet
 */
enum {
	HELLO_REQUEST			= 0x00,
	CLIENT_HELLO				= 0x01,
	SERVER_HELLO				= 0x02,
	CERTIFICATE					= 0x0B,
	SERVER_KEY_EXCHANGE	= 0x0C,
	CERTIFICATE_REQUEST		= 0x0D,
	SERVER_DONE				= 0x0E,
	CERTIFICATE_VERIFY		= 0x0F,
	CLIENT_KEY_EXCHANGE		= 0x10,
	FINISHED						= 0x14
};

typedef struct{
	uint16_t cipher_id;
	char *name;
	key_exchange_algorithm kx;
	authentication_algorithm au;
	uint16_t key_size;
	hash_algorithm hash;
}cipher_suite_t;

#endif

extern const int NUM_CIPHER_SUITE;

/*
 * Starting from cipher suite id retrieve the hash function
 * to be used in PRF
 */
const EVP_MD *get_hash_function(hash_algorithm h);

cipher_suite_t get_cipher_suite_by_id(uint16_t id);

cipher_suite_t get_cipher_suite_by_name(char *name);

int get_cipher_suites(key_exchange_algorithm kx, hash_algorithm h, authentication_algorithm au, cipher_suite_t array[]);
