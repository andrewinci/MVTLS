/**
 *	SSL/TLS Project
 *	\file ServerClientHello.h
 *
 *	This file is used to manage the client/server hello message of the handshake protocol
 *
 *	\date Created on 24/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef ServerClientHello_h
#define ServerClientHello_h

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "TLSConstants.h"
#include "HandshakeConstants.h"
#endif 

/** 
 * \struct random_data_t
 *	Contains the random part of the hello handshake message.
 */
typedef struct{

	/** UNIX time stamp */
	uint32_t UNIX_time;

	/** A cryptographic random byte stream of length 28*/
	uint8_t random_bytes[28];

}random_data_t;

/** \struct session_id_t
 * Contains info about TLS session. 
 * The sessions are used for connection recovering.
 */
typedef struct{

	/** Byte stream that specify the session id */
	unsigned char *session_id;

	/** The session byte stream length */
	uint8_t session_lenght;

}session_id_t;

/** \struct compression_methods_t 
 *	Contains info about the compression.
*/
typedef struct{
	/** Compression id length*/
	uint16_t length;

	/** Byte stream that specify the compression methods*/
	uint8_t *compression_id;

}compression_methods_t;

/** \struct server_client_hello_t
 *	Model a server/client hello message with all his field.
 *	Extension are not implemented yet.
 */
typedef struct{

	/** TLS version */
	uint16_t TLS_version; 

	/** Random struct: UNIX timestamp, random stream */
	random_data_t random;

	/** Session struct: session id, session length */
	session_id_t session_id;

	/** 
	 *	For the client hello this is list of supported cipher suite 
	 *	by client. For server hello it contains only one cipher suite.
	 */
	cipher_suite_t *cipher_suites;

	/**
	 * The space in byte used by the cipher suites. 
	 * Each cipher suite need 2 byte for his id.
	 */
	uint16_t cipher_suite_len;

	/**
	 * Compression struct
	 */
	compression_methods_t compression_methods;
}server_client_hello_t;
/**
 * Given the client hello message the function makes the server hello.
 * It chooses a random cipher suite among those provided by the client.
 * The function also fills the random field using the time stamp and a random generator (OpenSSL)
 *
 *	\param TLS_param: the connection parameters
 *	\param client_hello: the received client hello.
 *	\return the hello server handshake message
 */
handshake_t * make_server_hello(handshake_parameters_t *TLS_param, server_client_hello_t *client_hello);

/**
 * Given an array of cipher suites, make a client hello message.
 * The function also fills the random field using the time stamp and a random generator (OpenSSL)
 *
 *	\param client_random: return the random set in the client hello
 *	\param cipher_suite_list: an array of cipher suites to add to the client hello
 *	\param cipher_suite_len: the number of cipher suites in the list
 *	\return the client hello handshake message
 */
handshake_t * make_client_hello(unsigned char *client_random, cipher_suite_t cipher_suite_list[], int cipher_suite_len);

/**
 * Make a client hello message.
 * The function set the unix time stamp, random and the session, if given. 
 *
 * \param session: session id to recover
 * \return the handshake, it has to be deallocated
 */
server_client_hello_t *make_hello(session_id_t session);

/**
 * Serialize a server_hello struct into a byte stream.
 *
 *	\param hello: struct to serialize
 *	\param stream: a pointer to NULL. Will return the stream byte.
 *	\param streamLen: the return stream length
 *	\param mode: set SERVER_MODE for a server hello message, CLIENT_MODE for client hello message
 */
void serialize_client_server_hello(server_client_hello_t *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode);

/**
 * De-serialize a byte stream into a server_client_hello struct.
 *
 *	\param stream: the stream to de-serialize.
 *	\param streamLen: the stream length
 *	\param mode: set SERVER_MODE for a server hello message, CLIENT_MODE for client hello message
 */
server_client_hello_t *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode);

/**
 * Print details about the server/client hello.
 *
 *	\param h: the server client struct to print
 */
void print_hello(server_client_hello_t *h);

/**
 * Delloc memory of server_client_hello.
 * 
 *	\param h: the struct to deallocate
 */
void free_hello(server_client_hello_t *h);
