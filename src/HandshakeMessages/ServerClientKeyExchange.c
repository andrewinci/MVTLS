//
//  SSL/TLS Project
//  ServerClientKeyExchange.c
//
//  Created on 06/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/ClientKeyExchange.h"
#else
#include "ServerClientKeyExchange.h"
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

void PRF(const EVP_MD *hash, unsigned char *secret, int secret_len, char *label, int label_len, unsigned char *seed, int seed_len, int result_len, unsigned char **result){
    unsigned char *buff = malloc(result_len);
    *result = buff;
    
    //compute p_hash(secret,seed)
    //secret is equal to secret
    //seed is equal to label concatenate with seed
    unsigned char *seed_p = malloc(label_len+seed_len);
    memcpy(seed_p, label, label_len);
    memcpy(seed_p+label_len, seed, seed_len);
    
    //compute A_i
    int tot_len = 0;
    unsigned int a_len = label_len+seed_len;
    unsigned char *a = seed_p;
    
    while (tot_len<result_len) {
        unsigned char *temp = NULL;
        temp = HMAC(hash, secret, secret_len, a, a_len, NULL, &a_len);
        a = temp;
        memcpy(buff+tot_len, a, a_len);
        tot_len+=a_len;
    }
    free(seed_p);
}