/**
 *	SSL/TLS Project
 *	\file TLS.h
 *	This file provide a set of function for the TLS
 *	handshake. The function are used to make TLS message
 *	for both server and client.
 *
 *	\date Created on 13/01/16.
 *	\copyright Copyright © 2016 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#ifndef TLS_h
#define TLS_h
#include <stdio.h>
#include <time.h>
#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"
#include "Crypto.h"

/** Struct TLS_parameters_t 
 *	This struct contains all details about connection.
 *	It also contains data to complete the handshake.
 */
typedef struct{
	/** The TLS version*/
	uint16_t tls_version;

	/** Store the previous state in the handshake*/
	uint16_t previous_state;
	
	/** The cipher suite used choosen in the handshake*/
	cipher_suite_t cipher_suite;

	/** Client random, include the UNIX time stamp */
	unsigned char client_random[32];

	/** Server random, include the UNIX time stamp */
	unsigned char server_random[32];

	/** Server key exchange message */
	server_key_exchange_t *server_key_ex;

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

}TLS_parameters_t;

#endif /*TLS_h*/

				/*** CLIENT ***/

/* Functions to make message*/

/**
 * Given an array of cipher suites make a client hello message. 
 * The function also fills the random field using the UNIX time stamp and a random generator (OpenSSL)
 *
 *	\param client_random: the random set in the client hello
 *	\param cipher_suite_list: an array of cipher suites to add in the client hello
 *	\param cipher_suite_len: the number of cipher suites in the list
 *	\return the hello client handshake message
 */
handshake_t * make_client_hello(unsigned char *client_random, cipher_suite_t cipher_suite_list[], int cipher_suite_len);

/**
 * Given the information in TLS_parameter and the key exchange algorithm
 * return the handshake of the client key exchange. That includes to compute the 
 * pre-master key. It also computes the master secret and set in TLS_param.
 *
 *	\param TLS_param: the parameters of the connection
 *	\param key_ex_alg: the key exchange algorithm of the handshake
 *	\return the client key exchange handshake message 
 */
handshake_t * make_client_key_exchange(TLS_parameters_t *TLS_param, uint16_t key_ex_alg);

/**
 * Make the change cipher spec record message. This message is simple and 
 * doesn't require any parameter.
 *
 *	\return the change cipher spec record
 */
record_t * make_change_cipher_spec();

/**
 * Given the connection parameters compute the finished message.
 * Note: TLS protocol requires this message to be encrypted.
 *
 *	\param TLS_param: the connection parameters 
 *	\return the finished handshake message
 */
handshake_t * make_finished_message(TLS_parameters_t *TLS_param ) ;


				/**** SERVER ****/

/**
 * Given the client hello message the function makes the server hello.
 * It chooses a random cipher suite among those provided by the client. 
 * The function also fills the random field using the UNIX time stamp and a random generator (OpenSSL)
 *
 *	\param TLS_param: the connection parameters
 *	\param client_hello: the received client hello.
 *	\return the hello server handshake message
 */
handshake_t * make_server_hello(TLS_parameters_t *TLS_param, server_client_hello_t *client_hello);

/**
 * Make the certificate message for the server.
 * That message depends on the authentication algorithm hence we require the connection
 * parameters. The function also sets the certificate in the connection parameters for
 * further uses.
 *
 *	\param TLS_param: connection parameters
 *	\return the certificate handshake message
 */
handshake_t * make_certificate(TLS_parameters_t *TLS_param);

/**
 * Make the server key exchange handshake message. 
 * The function also sets the message in the connection parameters
 * to compute the master key in the client key exchange message.
 *
 *	\param TLS_param: connection parameters
 *	\return the server key exchange handshake message
 */
handshake_t * make_server_key_exchange(TLS_parameters_t *TLS_param);

/**
 * Make the server hello done message. This message is simple and 
 * doesn't require any parameter.
 *
 *	\return the server hello done handshake message
 */
handshake_t * make_server_hello_done();

/**
 * Append the handshake h to the handshake_messages field of TLS_param
 *	
 *	\param TLS_param: connection parameters
 *	\param h: the handshake to append
 */
void backup_handshake(TLS_parameters_t *TLS_param, handshake_t *h);
