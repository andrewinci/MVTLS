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
    
    unsigned char *result;
    uint16_t len;
    
    if(kx == DHE_KX){
    
        DHE_server_key_exchange *server_key_ex = (DHE_server_key_exchange*)server_key_exchange;

        int pLen = BN_num_bytes(server_key_ex->p), gLen = BN_num_bytes(server_key_ex->g), pubKeyLen = BN_num_bytes(server_key_ex->pubKey);
        
        *streamLen = 2+pLen+2+gLen+2+pubKeyLen+2+2+server_key_ex->signature_length;
        
        result = malloc(*streamLen);
        
        *stream = result;
        pLen = REV16(pLen);
        memcpy(result, &pLen, 2);
        result+=2;
        len = BN_bn2bin(server_key_ex->p, result);
        result+=len;
        
        gLen = REV16(gLen);
        memcpy(result, &gLen, 2);
        result+=2;
        
        len = BN_bn2bin(server_key_ex->g, result);
        result+=len;
        
        pubKeyLen = REV16(pubKeyLen);
        memcpy(result, &pubKeyLen, 2);
        result+=2;
        
        len = BN_bn2bin(server_key_ex->pubKey, result); //copy public key
        result+=len;
        
        //add signature
        
        memcpy(result, &(server_key_ex->sign_hash_alg), 2); //copy hash, sign alg
        result+=2;
        
        len = server_key_ex->signature_length;
        len = REV16(len);
        memcpy(result, &len, 2);
        result+=2;
        
        memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
 
    }else if(kx == ECDHE_KX){
        
        ECDHE_server_key_exchange *server_key_ex = (ECDHE_server_key_exchange*)server_key_exchange;
        
        //compute stream len
        // named_curve(1)  curve_name(2) pub_key_len(1) pub_key(..) signature_alg(2) signature_len(2) siganture(..)
        *streamLen = 1 + 2 + 1 + BN_num_bytes(server_key_ex->pub_key) + 2 + 2 + server_key_ex->signature_length;
        
        result = (unsigned char * )malloc(sizeof(char)*(*streamLen));
        *stream = result;
        
        //set named_curve mode
        *result = 0x03;
        result++;
        
        //set curve name
        uint16_t curve_name = server_key_ex->named_curve;
        curve_name = REV16(curve_name);
        memcpy(result, &curve_name, sizeof(uint16_t));
        result+=2;
        
        //convert and set public key
        *result = BN_num_bytes(server_key_ex->pub_key);
        result++;
        
        BN_bn2bin(server_key_ex->pub_key, result);
        result+=BN_num_bytes(server_key_ex->pub_key);
        
        //add signature
        
        memcpy(result, &(server_key_ex->sign_hash_alg), 2); //copy hash, sign alg
        result+=2;
        
        len = server_key_ex->signature_length;
        len = REV16(len);
        memcpy(result, &len, 2);
        result+=2;
        
        memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
    }
}

void *deserialize_server_key_exchange(uint32_t message_len, unsigned char *message, key_exchange_algorithm kx){
    if(kx == DHE_KX){
        DHE_server_key_exchange *server_key_ex = malloc(sizeof(DHE_server_key_exchange));
        uint16_t len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        server_key_ex->p = BN_bin2bn(message, len, NULL);
        
        message+=len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        server_key_ex->g = BN_bin2bn(message, len, NULL);
        
        message+=len;
        memcpy(&len, message, 2);
        message+=2;
        len = REV16(len);
        server_key_ex->pubKey = BN_bin2bn(message, len, NULL);
        message+=len;
        
        memcpy(&(server_key_ex->sign_hash_alg), message, 2);
        message+=2;
        
        memcpy(&(server_key_ex->signature_length), message, 2);
        message+=2;
        server_key_ex->signature_length = REV16(server_key_ex->signature_length);
        
        server_key_ex->signature = malloc(server_key_ex->signature_length);
        memcpy(server_key_ex->signature, message, server_key_ex->signature_length);
        message+=2;
        
        return server_key_ex;
    }
    else if (kx == ECDHE_KX){
        
        ECDHE_server_key_exchange *server_key_ex = malloc(sizeof(ECDHE_server_key_exchange));
        
        message++; //we already know that it is 0x03 for named_curve
        
        uint16_t curve_name;
        memcpy(&curve_name, message, sizeof(char)*2);
        server_key_ex->named_curve = REV16(curve_name);
        message+=2;
        
        uint8_t pubkey_len = *message;
        message++;
        server_key_ex->pub_key = BN_bin2bn(message, pubkey_len, NULL);
        
        memcpy(&(server_key_ex->sign_hash_alg), message, 2);
        message+=2;
        
        memcpy(&(server_key_ex->signature_length), message, 2);
        message+=2;
        server_key_ex->signature_length = REV16(server_key_ex->signature_length);
        
        server_key_ex->signature = malloc(server_key_ex->signature_length);
        memcpy(server_key_ex->signature, message, server_key_ex->signature_length);
        message+=2;
        
        return server_key_ex;
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

void free_server_key_exchange(void *server_key_ex, cipher_suite_t cipher_suite){
    if(server_key_ex!=NULL && cipher_suite.kx == DHE_KX){
        DHE_server_key_exchange *params = (DHE_server_key_exchange*)server_key_ex;
        BN_free(params->g);
        BN_free(params->p);
        BN_free(params->pubKey);
        free(params->signature);
        free(params);
    }
        
}