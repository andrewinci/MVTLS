//
//  SSL/TLS Project
//  handshakeConstants.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
// This file contains a set of constants used in 
// the handshake protocol and some function 
//

#ifndef handshakeConstants_h
#define handshakeConstants_h
#include <stdio.h>
#include <stdint.h>
#include <openssl/hmac.h>

#define REV16(value)({(value & 0x00FFU) << 8 | (value & 0xFF00U) >> 8;})
#define REV32(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})

//Cipher ID 	 Name 	 Kx 	 Au 	 Bits 	 Mac
typedef enum{
    RSA_KX = 1,
    DHE_KX = 2,
    ECDHE_KX = 3
}key_exchange_algorithm;

typedef enum{
    RSA_AU = 1,
    DSS_AU = 2,
    ECDSA_AU = 3
}authentication_algorithm;

typedef enum
{
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6
}hash_algorithm;

typedef struct{
    uint16_t cipher_id;
    char *name;
    key_exchange_algorithm kx;
    authentication_algorithm au;
    uint16_t key_size;
    hash_algorithm hash;
    
}cipher_suite_t;

#endif

#ifndef channel_mode_enum
#define channel_mode_enum
typedef enum{
    SERVER_MODE,
    CLIENT_MODE
}channel_mode;
#endif

cipher_suite_t get_cipher_suite(uint16_t id);

/*
 * Starting from cipher suite id retrieve the hash function
 * to be used in PRF
 */
const EVP_MD *get_hash_function(hash_algorithm h);

/*
 * Record Version
 */
#ifndef enum_record_version
#define enum_record_version
typedef enum{
    SSL3_0 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303
}TLS_version;
#endif

/*
 * Types of handshake packet
 */
#ifndef enum_handshake_type
#define enum_handshake_type
enum {
    HELLO_REQUEST           = 0x00,
    CLIENT_HELLO            = 0x01,
    SERVER_HELLO            = 0x02,
    CERTIFICATE             = 0x0B,
    SERVER_KEY_EXCHANGE     = 0x0C,
    CERTIFICATE_REQUEST     = 0x0D,
    SERVER_DONE             = 0x0E,
    CERTIFICATE_VERIFY      = 0x0F,
    CLIENT_KEY_EXCHANGE     = 0x10,
    FINISHED                = 0x14
};
#endif
