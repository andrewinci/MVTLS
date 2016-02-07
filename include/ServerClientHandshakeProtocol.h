/**
 *	SSL/TLS Project
 *	\file ServerClientHandshakeProtocol.h
 *
 *	This file is used to manage the handshake protocol
 *
 *	\date Created on 27/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef ServerClientHandshakeProtocol_h

#define ServerClientHandshakeProtocol_h

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "ServerClientRecordProtocol.h"
#include "TLSConstants.h"

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientHello.h"
#include "HandshakeMessages/Certificate.h"
#include "HandshakeMessages/ServerKeyExchange.h"
#include "HandshakeMessages/ClientKeyExchange.h"
#else
#include "ServerClientHello.h"
#include "Certificate.h"
#include "ClientKeyExchange.h"
#include "ServerKeyExchange.h"
#endif

#endif


/**
 * Given the information in TLS_parameter and the key exchange algorithm
 * return the handshake of the client key exchange. That includes to compute the
 * pre-master key. It also computes the master secret and set in TLS_param.
 *
 *	\param TLS_param: the parameters of the connection
 *	\param key_ex_alg: the key exchange algorithm of the handshake
 *	\return the client key exchange handshake message
 */
handshake_t * make_client_key_exchange(handshake_parameters_t *TLS_param, uint16_t key_ex_alg);

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
handshake_t * make_finished_message(handshake_parameters_t *TLS_param ) ;


/**** SERVER ****/



/**
 * Make the certificate message for the server.
 * That message depends on the authentication algorithm hence we require the connection
 * parameters. The function also sets the certificate in the connection parameters for
 * further uses.
 *
 *	\param TLS_param: connection parameters
 *	\return the certificate handshake message
 */
handshake_t * make_certificate(handshake_parameters_t *TLS_param);

/**
 * Make the server key exchange handshake message.
 * The function also sets the message in the connection parameters
 * to compute the master key in the client key exchange message.
 *
 *	\param TLS_param: connection parameters
 *	\return the server key exchange handshake message
 */
handshake_t * make_server_key_exchange(handshake_parameters_t *TLS_param);

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
void backup_handshake(handshake_parameters_t *TLS_param, handshake_t *h);

    /************ SEND SERIALIZE DE_SERIALIZE **************/

/**
* Send a handshake through a channel
* 
*	\param ch: the channel to use
*	\param h:	the handshake to send
*	\return 1 if the send is succeeded, 0 otherwise
*/
int send_handshake(channel_t *ch, handshake_t *h);

/**
 * Serialize a handshake into a byte stream
 *
 *	\param h: the handshake to serialize
 *	\param stream: a pointer to NULL, it will filled with the serialized handshake
 *	\param streamLen: the length of the serialized message
 */
void serialize_handshake(handshake_t *h, unsigned char **stream, uint32_t *streamLen);

/**
 * De-serialize a stream of byte into an handshake. 
 *
 *	\param message: the serialized handshake 
 *	\param messageLen: the message length
 *	\return alloc and return a handshake struct
 */
handshake_t *deserialize_handshake(unsigned char *message, uint32_t messageLen);

/**
 * Print the handshake struct
 *
 *	\param h: handshake to print
 *	\param verbosity: how many details to print (0 none, 1 the binary, 2 details,3 record)
 *	\param kx: the key exchange algorithm, useful in key_echange messages
 */
void print_handshake(handshake_t *h, int verbosity, key_exchange_algorithm kx);

/**
 * Dealloc memory of handshake struct
 * 
 *	\param h: the handshake to free
 */
void free_handshake(handshake_t *h);
