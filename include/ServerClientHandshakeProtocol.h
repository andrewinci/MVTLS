/**
 *	SSL/TLS Project
 *	\file ServerClientHandshakeProtocol.h
 *
 *	This file is used to mange the handshake protocol
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
#include "HandshakeMessages/ServerClientKeyExchange.h"
#else
#include "ServerClientHello.h"
#include "Certificate.h"
#include "ServerClientKeyExchange.h"
#endif

#endif

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
