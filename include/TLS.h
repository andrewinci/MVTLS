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

#endif /* TLS_h */

#ifndef TLS_parameter_enum
#define TLS_parameter_enum
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
}TLS_parameters;
#endif

                /*** CLIENT ***/


/* Functions for make message*/

handshake * make_client_hello(unsigned char *client_random);

handshake * make_client_key_exchange(TLS_parameters *TLS_param, uint16_t key_ex_alg);

record * make_change_cipher_spec();

handshake * make_finished_message(TLS_parameters *TLS_param ) ;


                /**** SERVER ****/

/* Functions for send handshake packet */
handshake * make_server_hello(TLS_parameters *TLS_param, handshake_hello *client_hello);

handshake * make_certificate(TLS_parameters *TLS_param);

handshake * make_server_key_exchange(TLS_parameters *TLS_param);

handshake * make_server_hello_done();

DHE_server_key_exchange * make_DHE_server_key_exchange(TLS_parameters *TLS_param);

ECDHE_server_key_exchange * make_ECDHE_server_key_exchange(TLS_parameters *TLS_param);

/*
 * This function appends to handshake_messages the handshake h
 */
void backup_handshake(TLS_parameters *TLS_param, handshake *h);