/**
 *	SSL/TLS Project
 *	\file ServerClientKeyExchange.h
 *
 *	This file contains functions for manage the server/client key exchange
 *	and respective structs.
 *
 *	\date Created on 06/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef ServerClientKeyExchange_h
#define ServerClientKeyExchange_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

#ifdef MAKEFILE
#include "../TLSConstants.h"
#else
#include "TLSConstants.h"
#endif


/**
	/struct ecdhe_server_key_exchange_t
	Model the ECDHE server key exchange message of the handshake protocol.
	The named curve mode is the only used.
 */
typedef struct{
	/** Curve name*/
	uint16_t named_curve;

	/** Public key*/
	BIGNUM *pub_key;

	/** First byte to specify the signature algorithm
		second byte to specify the hash algorithm */
	uint16_t sign_hash_alg; 

	/** Signature length*/
	unsigned int signature_length;

	/** Signature byte stream*/
	unsigned char *signature;

}ecdhe_server_key_exchange_t;

/**
	/struct dhe_server_key_exchange_t
	Model the DHE server key exchange message of the handshake protocol.
 */
typedef struct{

	/** Prime field */
	BIGNUM *p;

	/** Field generator*/
	BIGNUM *g;

	/** DH public key. pubkey = (g^k mod p) where k is the private key*/
	BIGNUM *pubKey;

	/** First byte to specify the signature algorithm
	second byte to specify the hash algorithm */
	uint16_t sign_hash_alg; 

	/** Signature length*/
	unsigned int signature_length;

	/** Signature byte stream*/
	unsigned char *signature;

}dhe_server_key_exchange_t;

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
	\def server_key_exchange_t
	The general server key exchange message. 
	It can be ECDHE or DHE, for this reason we ask for key exchange algorithm 
	each time that we use that type.
*/
typedef void server_key_exchange_t;

#endif
					/******* SERVER KEY EXCHANGE *******/
/**
 * Serialize a server key exchange message into a byte stream.
 * 
 *	\param server_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 *	\param kx: the key exchange method of the handshake
 */
void serialize_server_key_exchange(server_key_exchange_t *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx);

/**
 * De-serialize a server key exchange byte stream message into the appropriate 
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\param kx: the key exchange method of the handshake
 *	\return the de-serialized server_key_excahnge message.
 */
server_key_exchange_t *deserialize_server_key_exchange(unsigned char *message, uint32_t message_len, key_exchange_algorithm kx);

/**
 * Print details about the server key exchange message
 *
 *	\param server_key_ex: the message to print
 *	\param kx: the key exchange method of the handshake
 */
void print_server_key_exchange(server_key_exchange_t *server_key_exchange, key_exchange_algorithm kx);

/**
 * Dealloc memory of server key exchange.
 * 
 *	\param server_key_ex: the server key exchange message to deallocate
 *	\param kx: the key exchange method of the handshake
 */
void free_server_key_exchange(server_key_exchange_t *server_key_ex, key_exchange_algorithm kx);

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
 *	\param client_key_ex: the message to print
 *	\param kx: the key exchange method of the handshake
 */
void print_client_key_exchange(client_key_exchange_t *client_key_exchange);

/**
 * Delloc memory of client key exchange.
 * 
 *	\param client_key_ex: the client key exchange message to deallocate
 */
void free_client_key_exchange(client_key_exchange_t *client_key_exchange);
