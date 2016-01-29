//
//  TLS.h
//  SSLXcodeProject
//
//  Created by Darka on 13/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#ifndef TLS_h
#define TLS_h
#include <stdio.h>
#include <time.h>
#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"
#include "Crypto.h"

typedef struct{
    uint16_t tls_version;
    uint16_t previous_state;
    cipher_suite_t cipher_suite;
    
    unsigned char client_random[32];
    unsigned char server_random[32];
    
    void *server_key_ex;
    
    unsigned char *master_secret;
    int master_secret_len;
    
    int handshake_messages_len;
    unsigned char *handshake_messages;
    
    X509 *server_certificate;
    
    BIGNUM *private_key;
}TLS_parameters_t;

#endif /*TLS_h*/

                /*** CLIENT ***/


/* Functions for make message*/

handshake_t * make_client_hello(unsigned char *client_random, cipher_suite_t cipher_suite_list[], int cipher_suite_len);

handshake_t * make_client_key_exchange(TLS_parameters_t *TLS_param, uint16_t key_ex_alg);

void make_RSA_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param);

void make_DHE_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param);

void make_ECDHE_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param);

record_t * make_change_cipher_spec();

handshake_t * make_finished_message(TLS_parameters_t *TLS_param ) ;


                /**** SERVER ****/

/* Functions for send handshake packet */
handshake_t * make_server_hello(TLS_parameters_t *TLS_param, handshake_hello_t *client_hello);

handshake_t * make_certificate(TLS_parameters_t *TLS_param);

handshake_t * make_server_key_exchange(TLS_parameters_t *TLS_param);

handshake_t * make_server_hello_done();

dhe_server_key_exchange_t * make_DHE_server_key_exchange(TLS_parameters_t *TLS_param);

ecdhe_server_key_exchange_t * make_ECDHE_server_key_exchange(TLS_parameters_t *TLS_param);

/*
 * This function appends to handshake_messages the handshake h
 */
void backup_handshake(TLS_parameters_t *TLS_param, handshake_t *h);
