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
#include "Crypto.h"

#ifdef MAKEFILE
#include "../TLSConstants.h"
#else
#include "TLSConstants.h"
#endif


#endif /* ClientKeyExchange_h */


                     /********** SIGNATURES **************/
/**
 * Verify the server_key_exchange message for a DHE key exchange.
 *
 *	\param certificate: the certificate to use to verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

/**
 * Verify the server_key_exchange message for a ECDHE key exchange.
 *
 *	\param certificate: the certificate to use to verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au);

                                /******* CLIENT KEY EXCHANGE *******/

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
