/**
 *	SSL/TLS Project
 *	\file ClientKeyExchange.h
 *
 *	This file contains functions to manage the client key exchange
 *	and respective structs.
 *
 *	\date Created on 03/01/16.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */


#ifndef ClientKeyExchange_h
#define ClientKeyExchange_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include "ServerKeyExchange.h"
#include "HandshakeConstants.h"
#include "PRF.h"

#ifdef MAKEFILE
#include "../HandshakeConstants.h"
#else
#include "HandshakeConstants.h"
#endif


#endif /* ClientKeyExchange_h */

/**
	/struct client_key_exchange_t
	Model the client key exchange message of the handshake protocol.
 */
typedef struct{

	/** Key length */
	uint16_t key_length;

	/** Key byte stream */
	unsigned char *key;

}client_key_exchange_t;

/**
 * Serialize a client key exchange message into a byte stream.
 *
 *	\param client_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 */
void serialize_client_key_exchange(client_key_exchange_t *client_key_exchange, unsigned char **stream, uint32_t *streamLen);

/**
 * De-serialize a client key exchange byte stream message into the appropriate
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\return the de-serialized client key exchange message
 */
client_key_exchange_t *deserialize_client_key_exchange(unsigned char *message, uint32_t message_len);

/**
 * Print details about the client key exchange message
 *
 *	\param client_key_exchange: the message to print
 */
void print_client_key_exchange(client_key_exchange_t *client_key_exchange);

/**
 * Delloc memory of client key exchange.
 *
 *	\param client_key_exchange: the client key exchange message to deallocate
 */
void free_client_key_exchange(client_key_exchange_t *client_key_exchange);
