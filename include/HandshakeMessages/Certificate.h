/**
 *	SSL/TLS Project
 *	\file Certificate.h
 *
 *	This file contains functions to manage the certificate message.
 *
 *	\date Created on 28/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifndef Certificate_h
#define Certificate_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "HandshakeConstants.h"

#endif

/** \struct certificate_message_t
* Certificate message struct.
* Model fields of the certificate message.	
*/
typedef struct{

	/** Certificate message length */
	uint32_t cert_length;

	/** X509 certificate */
	X509 *X509_certificate;

}certificate_message_t;

/**
 * Make the certificate message for the server.
 * That message depends on the authentication algorithm hence we require the connection
 * parameters. The function also sets the certificate in the connection parameters for
 * further uses.
 *
 *	\param connection_parameters: connection parameters
 *	\return the certificate handshake message
 */
handshake_t * make_certificate(handshake_parameters_t *connection_parameters);

/**
 * Given the certificate file name create a certificate message struct
 * that encapsulate it.
 *
 *	\param cert_file_name: certificate file name including path
 *	\return the certificate message struct
 */
certificate_message_t *make_certificate_message(char *cert_file_name);

/**
 * Serialize the certificate message into a byte stream
 *
 *	\param cert: the message to serialize
 *	\param stream: the return stream. Must point to NULL.
 *	\param len: the stream length
 */
void serialize_certificate_message(certificate_message_t *cert, unsigned char **stream, uint32_t *len);

/**
 * De-serialize a byte stream into a certificate_message.
 *
 *	\param stream: the byte stream to de-serialize
 *	\param len: the byte stream length
 *	\return the certificate_message
 */
certificate_message_t *deserialize_certificate_message(unsigned char *stream, uint32_t len);

/**
 * Dealloc memory of certificate_message
 * 
 *	\param cert: the certificate message to deallocate
 */
void free_certificate_message(certificate_message_t *cert);
