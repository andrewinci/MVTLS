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
#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"
#include "Crypto.h"

#endif /* TLS_h */

                /*** CLIENT ***/


/* Functions for make message*/

handshake * make_client_hello(unsigned char *client_random);

void send_RSA_client_key_exchange(channel *client2server, TLS_parameters *TLS_param);

void send_DH_client_key_exchange(channel *client2server, TLS_parameters *TLS_param);

record * make_change_cipher_spec();

handshake * make_finished_message(TLS_parameters *TLS_param ) ;

/* Functions for process received handshake (saving data for next steps)*/

void process_server_hello(TLS_parameters *TLS_param, handshake *h);

void process_certificate(TLS_parameters *TLS_param, handshake *h);



                /**** SERVER ****/


/* Functions for manage key exchange */
void manage_RSA_client_key_exchange(TLS_parameters *TLS_param, handshake *h);

void manage_DHE_server_key_exchange(handshake *h);

/* Functions for send handshake packet */
handshake * make_server_hello(TLS_parameters *TLS_param, handshake_hello *client_hello);

handshake * make_certificate(TLS_parameters *TLS_param);

handshake * make_server_key_exchange(TLS_parameters *TLS_param);

handshake * make_server_hello_done();

/*
 * This function appends to handshake_messages the handshake h
 */
void backup_handshake(TLS_parameters *TLS_param, handshake *h);