//
//  HandshakeConstants.h
//  TLSProject
//
//  Created by Darka on 06/02/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#ifndef HandshakeConstants_h
#define HandshakeConstants_h

#include "TLSConstants.h"
/** \struct TLS_parameters_t
 *	This struct contains all details about connection.
 *	It also contains data to complete the handshake.
 */
typedef struct{
    
    /** The TLS version*/
    uint16_t tls_version;
    
    /** Store the previous state in the handshake*/
    uint16_t previous_state;
    
    /** The cipher suite used chosen in the handshake*/
    cipher_suite_t cipher_suite;
    
    /** Client random, include the UNIX time stamp */
    unsigned char client_random[32];
    
    /** Server random, include the UNIX time stamp */
    unsigned char server_random[32];
    
    /** Server key exchange message */
    void *server_key_ex;
    
    /** Session master secret */
    unsigned char *master_secret;
    
    /** Master secret length */
    int master_secret_len;
    
    /** The backup of handshake messages exchanged during handshake*/
    unsigned char *handshake_messages;
    
    /** Backup stream length */
    int handshake_messages_len;
    
    /** The server certificate */
    X509 *server_certificate;
    
    /** The private key for the key exchange */
    BIGNUM *private_key;
    
}handshake_parameters_t;

/**
 * \struct handshake_t
 * Handshake protocol struct.
 * Model fields of handshake messages.
 */
typedef struct{
    /** Handshake type:
     HELLO_REQUEST(0x00), CLIENT_HELLO(0x01), SERVER_HELLO(0x02),
     CERTIFICATE(0x0B), SERVER_KEY_EXCHANGE(0x0C), CERTIFICATE_REQUEST(0x0D),
     SERVER_DONE(0x0E), CERTIFICATE_VERIFY(0x0F), CLIENT_KEY_EXCHANGE(0x10),
     FINISHED(0x14)
     */
    uint8_t type;
    
    /** Message length*/
    uint32_t length;
    
    /** Handshake binary message */
    unsigned char *message;
}handshake_t;

#endif /* HandshakeConstants_h */
