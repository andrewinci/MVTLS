//
//  SSL/TLS Project
//  handshakeConstants.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
// This file contains a set of constants used in 
// the handshake protocol
//

#ifndef handshakeConstants_h
#define handshakeConstants_h
#endif

typedef enum{
    SERVER_MODE,
    CLIENT_MODE
}channel_mode;

/*
 * Cipher suite ids
 */
enum {
    TLS_NULL_WITH_NULL_NULL               = 0x00,
    //The following definitions require that the server provide
    //an RSA certificate that can be used for key exchange
    TLS_RSA_WITH_NULL_MD5                 = 0x01,
    TLS_RSA_WITH_NULL_SHA                 = 0x02,
    TLS_RSA_WITH_NULL_SHA256              = 0x3B,
    TLS_RSA_WITH_RC4_128_MD5              = 0x04,
    TLS_RSA_WITH_RC4_128_SHA              = 0x05,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA         = 0x0A,
    TLS_RSA_WITH_AES_128_CBC_SHA          = 0x2F,
    TLS_RSA_WITH_AES_256_CBC_SHA          = 0x35,
    TLS_RSA_WITH_AES_128_CBC_SHA256       = 0x3C,
    TLS_RSA_WITH_AES_256_CBC_SHA256       = 0x3D,
    
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA      = 0x0D,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA      = 0x10,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA     = 0x13,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA     = 0x16,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA       = 0x30,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA       = 0x31,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA      = 0x32,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA      = 0x33,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA       = 0x36,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA       = 0x37,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA      = 0x38,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA      = 0x39,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256    = 0x3E,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256    = 0x3F,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256   = 0x40,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256   = 0x67,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256    = 0x68,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256    = 0x69,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256   = 0x6A,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256   = 0x6B,

    TLS_DH_anon_WITH_RC4_128_MD5          = 0x18,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA     = 0x1B,
	TLS_DH_anon_WITH_AES_128_CBC_SHA      = 0x34,
	TLS_DH_anon_WITH_AES_256_CBC_SHA      = 0x3A,
	TLS_DH_anon_WITH_AES_128_CBC_SHA256   = 0x6C,
	TLS_DH_anon_WITH_AES_256_CBC_SHA256   = 0x6D
};
