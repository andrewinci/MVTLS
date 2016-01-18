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

#ifndef server_key_exchange_structs
#define server_key_exchange_structs



typedef struct{
    
    BIGNUM *p;
    
    BIGNUM *g;
    
    BIGNUM *pubKey;
    
    //signature hash algorithm,  1 for signature alg, 1 for hash,
    uint16_t sign_hash_alg; //RSA, SHA512 0x0106 !!! we not rev the byte !!!
    
    uint16_t signature_length;
    
    unsigned char *signature;
    
}DH_server_key_exchange;

typedef struct{
    
    uint16_t key_length;
    
    unsigned char *key;
    
}client_key_exchange;

#endif

void serialize_server_key_exchange(void *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx);

void *deserialize_server_key_exchange(uint32_t message_len, unsigned char *message, key_exchange_algorithm kx);

void serialize_client_key_exchange(client_key_exchange *client_key_exchange, unsigned char **stream, uint32_t *streamLen);

void *deserialize_client_key_exchange(uint32_t message_len, unsigned char *message);

void free_DH_server_key_exchange(DH_server_key_exchange *params);
