//
//	SSL/TLS Project
//	ServerClientHello.h
//
//	Created on 24/12/15.
//	Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
//
//	This file is used to manade the client/server hello message of the handshake protocol
//
#ifndef ServerClientHello_h
#define ServerClientHello_h

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "TLSConstants.h"
#endif /* ServerClientHello_h */

// 32-bit of random
typedef struct{
	uint32_t UNIX_time;
	uint8_t random_bytes[28];
}random_data_t;

// Session ID
typedef struct{
	uint8_t session_lenght;
	unsigned char *session_id;
}session_id_t;

// Compression methods
typedef struct{
	uint16_t length;
	uint8_t *compression_id;
}compression_methods_t;

// Handshake hello packet
typedef struct{
	uint16_t TLS_version; 
	random_data_t random;
	session_id_t session_id;
	uint16_t cipher_suite_len;
	cipher_suite_t *cipher_suites;
	compression_methods_t compression_methods;
}server_client_hello_t;

/*
 * Make a client hello message
 * session: session id to recover
 * return the handshake, it has to be deallocated
 */
server_client_hello_t *make_hello(session_id_t session);

/*
 * Convert a ClientHello/ServerHello into a stream of streamLen byte
 */
void serialize_client_server_hello(server_client_hello_t *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode);

/*
 * Build an handshake type from a byte stream
 * stream: poiter to the byte stream
 * streamLen: stream length
 * mode: define if clientHello or serverHello (differenze in the lenght)
 */
server_client_hello_t *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode);

void free_hello(server_client_hello_t *h);

void print_hello(server_client_hello_t *h);
