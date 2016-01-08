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

#endif

#define PRE_MASTER_KEY_LEN 48

#ifndef channel_mode_enum
#define channel_mode_enum
typedef enum{
    SERVER_MODE,
    CLIENT_MODE
}channel_mode;
#endif

/*
 * Key exchange algoritm
 */
#ifndef key_exchange_algorithm_enum
#define key_exchange_algorithm_enum
typedef enum{
    RSA_KX, DH_RSA_KX, DH_DSS_KX
}key_exchange_algorithm;
#endif

/*
 * Starting from cipher suite id retrieve the hash function
 * to be used in PRF
 */
const EVP_MD *get_hash_function(uint16_t cipher_suite_Id);

/*
 * Starting form cipher suite id retrieve the key excahnge alghoritm
 */
key_exchange_algorithm get_kx_algorithm(uint16_t cipher_suite_Id);

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

/*
 * Cipher suite ids
 */
#ifndef cipher_suite_ids_enum
#define cipher_suite_ids_enum
enum {
    //RSA
    TLS_RSA_WITH_NULL_MD5					= 0x0001,
    TLS_RSA_WITH_NULL_SHA					= 0x0002,
    TLS_RSA_WITH_RC4_128_MD5				= 0x0004,
    TLS_RSA_WITH_RC4_128_SHA				= 0x0005,
    TLS_RSA_WITH_IDEA_CBC_SHA				= 0x0007,
    TLS_RSA_WITH_DES_CBC_SHA				= 0x0009,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA			= 0x000A,
    TLS_RSA_PSK_WITH_NULL_SHA				= 0x002E,
    TLS_RSA_WITH_AES_128_CBC_SHA			= 0x002F,
    TLS_RSA_WITH_AES_256_CBC_SHA			= 0x0035,
    TLS_RSA_WITH_NULL_SHA256				= 0x003B,
    TLS_RSA_WITH_AES_128_CBC_SHA256         = 0x003C,
    TLS_RSA_WITH_AES_256_CBC_SHA256         = 0x003D,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA		= 0x0041,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA		= 0x0084,
    TLS_RSA_PSK_WITH_RC4_128_SHA			= 0x0092,
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA		= 0x0093,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA		= 0x0094,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA		= 0x0095,
    TLS_RSA_WITH_SEED_CBC_SHA				= 0x0096,
    TLS_RSA_WITH_AES_128_GCM_SHA256         = 0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384         = 0x009D,
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256     = 0x00AC,
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384     = 0x00AD,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256     = 0x00B6,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384     = 0x00B7,
    TLS_RSA_PSK_WITH_NULL_SHA256			= 0x00B8,
    TLS_RSA_PSK_WITH_NULL_SHA384			= 0x00B9,
    
    //DH DSS
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA	= 0x000B,
    TLS_DH_DSS_WITH_DES_CBC_SHA             = 0x000C,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA		= 0x000D,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA         = 0x0030,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA         = 0x0036,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256		= 0x003E,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA	= 0x0042,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256		= 0x0068,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA	= 0x0085,
    TLS_DH_DSS_WITH_SEED_CBC_SHA			= 0x0097,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256		= 0x00A4,
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384		= 0x00A5,
    
    //DH RSA
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA	= 0x000E,
    TLS_DH_RSA_WITH_DES_CBC_SHA             = 0x000F,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA		= 0x0010,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA         = 0x0031,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA         = 0x0037,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256		= 0x003F,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA	= 0x0043,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256		= 0x0069,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA	= 0x0086,
    TLS_DH_RSA_WITH_SEED_CBC_SHA			= 0x0098,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256		= 0x00A0,
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384		= 0x00A1
    
};
#endif



