//
//  SSL/TLS Project
//  ServerClientKeyExchange.c
//
//  Created on 06/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientKeyExchange.h"
#else
#include "ServerClientKeyExchange.h"
#endif

void serialize_server_key_exchange(void *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx){
    
    if(kx == DHE_RSA_KX){
    
        DH_server_key_exchange *dh_server_key_ex = (DH_server_key_exchange*)server_key_exchange;
        unsigned char *buf;
        uint16_t len;
        int pLen = BN_num_bytes(dh_server_key_ex->p), gLen = BN_num_bytes(dh_server_key_ex->g), pubKeyLen = BN_num_bytes(dh_server_key_ex->pubKey);
        
        *streamLen = 2+pLen+2+gLen+2+pubKeyLen+2+2+dh_server_key_ex->signature_length;
        
        buf = malloc(*streamLen);
        *stream = buf;
        pLen = REV16(pLen);
        memcpy(buf, &pLen, 2);
        buf+=2;
        len = BN_bn2bin(dh_server_key_ex->p, buf);
        buf+=len;
        
        gLen = REV16(gLen);
        memcpy(buf, &gLen, 2);
        buf+=2;
        
        len = BN_bn2bin(dh_server_key_ex->g, buf);
        buf+=len;
        
        pubKeyLen = REV16(pubKeyLen);
        memcpy(buf, &pubKeyLen, 2);
        buf+=2;
        
        len = BN_bn2bin(dh_server_key_ex->pubKey, buf); //copy public key
        buf+=len;
        
        memcpy(buf, &(dh_server_key_ex->sign_hash_alg), 2); //copy hash, sign alg
        buf+=2;
        
        len = dh_server_key_ex->signature_length;
        len = REV16(len);
        memcpy(buf, &len, 2);
        buf+=2;
        
        memcpy(buf, dh_server_key_ex->signature, dh_server_key_ex->signature_length);
    }

}

void *deserialize_server_key_exchange(uint32_t message_len, unsigned char *message, key_exchange_algorithm kx){
    if(kx == DHE_RSA_KX){
        DH_server_key_exchange *dh_server_key_ex = malloc(sizeof(DH_server_key_exchange));
        uint16_t len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        dh_server_key_ex->p = BN_bin2bn(message, len, NULL);
        
        message+=len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        dh_server_key_ex->g = BN_bin2bn(message, len, NULL);
        
        message+=len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        dh_server_key_ex->pubKey = BN_bin2bn(message, len, NULL);
        
        message+=len;
        memcpy(&(dh_server_key_ex->sign_hash_alg), message, 2);
        message+=2;
        memcpy(&(dh_server_key_ex->signature_length), message, 2);
        message+=2;
        dh_server_key_ex->signature = malloc(dh_server_key_ex->signature_length);
        memcpy(dh_server_key_ex->signature, message, dh_server_key_ex->signature_length);
        message+=2;
        
        return dh_server_key_ex;
    }
    return NULL;
}

void serialize_client_key_exchange(client_key_exchange *client_key_exchange, unsigned char **stream, uint32_t *streamLen){
    
        //the first 2 message byte are the key length
        unsigned char *buff = malloc(client_key_exchange->key_length+2);
        *stream = buff;
        //add lenght
        uint16_t temp = REV16(client_key_exchange->key_length);
        memcpy(buff, &temp, 2);
        buff+=2;
        //add key
        memcpy(buff, client_key_exchange->key, client_key_exchange->key_length);
        *streamLen=client_key_exchange->key_length+3;
}

void *deserialize_client_key_exchange(uint32_t message_len, unsigned char *message){
        client_key_exchange *rsa_server_key_ex = malloc(sizeof(client_key_exchange));
        memcpy(&(rsa_server_key_ex->key_length), message, 2);
        message+=2;
        
        rsa_server_key_ex->key_length = REV16(rsa_server_key_ex->key_length);
        
        unsigned char *buff = malloc(rsa_server_key_ex->key_length);
        rsa_server_key_ex->key = buff;
        memcpy(buff, message, rsa_server_key_ex->key_length);
        
        return rsa_server_key_ex;
}

void free_DH_server_key_exchange(DH_server_key_exchange *params){
    BN_free(params->g);
    BN_free(params->p);
    BN_free(params->pubKey);
    free(params->signature);
}