//
//  SSL/TLS Project
//  ClientKeyExchange.c
//
//  Created on 06/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/ClientKeyExchange.h"
#else
#include "ClientKeyExchange.h"
#endif

void serialize_key_exchange(uint32_t key_length, unsigned char *encrypted_premaster_key, unsigned char **stream, uint32_t *len, key_exchange_algorithm kx){
    if(kx == RSA_KX){
        //the first 3 message byte are the key length
        unsigned char *buff = malloc(key_length+2);
        *stream = buff;
        //add lenght
        uint32_t temp = REV32(key_length)>>8;
        memcpy(buff, &temp, 3);
        buff+=3;
        //add key
        memcpy(buff, encrypted_premaster_key, key_length);
        *len=key_length+3;
    }
}

void deserialize_key_exchange(uint32_t message_len, unsigned char *message, unsigned char **encrypted_premaster_key, uint32_t *key_len, key_exchange_algorithm kx){
    if(kx == RSA_KX){
        memcpy(key_len, message, 3);
        message+=3;
        
        *key_len = REV32(*key_len)>>8;
        unsigned char *buff = malloc(*key_len);
        *encrypted_premaster_key = buff;
        memcpy(buff, message, *key_len);
    }
}