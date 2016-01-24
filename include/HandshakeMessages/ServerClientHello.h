//
//  SSL/TLS Project
//  ServerClientHello.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
// This file is used to manade the client/server hello message
// of the handshake protocol
//
#ifndef ServerClientHello_h
#define ServerClientHello_h

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "handshakeConstants.h"
#endif /* ServerClientHello_h */

// 32-bit of random
typedef struct {
    uint32_t UNIX_time;
    uint8_t random_bytes[28];
} random_data;

// Session ID
typedef struct session_id_t {
    uint8_t session_lenght;
    uint8_t *session_id;
} session_id;

// (Useless) Compression methods
typedef struct compression_methods_t {
    uint16_t length;
    uint8_t compression_id;
} compression_methods;

// Handshake hello packet
typedef struct{
    uint16_t TLS_version; 
    random_data random;							// 32 bytes
    session_id session_id;					// 1+session_id.session_lenght bytes
    uint16_t cipher_suite_len;
    cipher_suite_t *cipher_suites;			// 1+2*cipher_suites.lenght bytes
    compression_methods compression_methods;// 3 bytes
} handshake_hello;

/*
 * Make a client hello message
 * session : session id to recover
 * return the handshake, it has to be deallocated
 */
handshake_hello *make_hello(session_id session);

/*
 * Convert a ClientHello/ServerHello into a stream of streamLen byte
 */
void serialize_client_server_hello(handshake_hello *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode);

/*
 * Build an handshake type from a byte stream
 * stream    : poiter to the byte stream
 * streamLen : stream length
 * mode : define if clientHello or serverHello (differenze in the lenght)
 */
handshake_hello *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode);

void free_hello(handshake_hello *h);

void print_hello(handshake_hello *h);