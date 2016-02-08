/**
 *	SSL/TLS Project
 *	\file Certificate.c
 *
 *	This file contains functions to manage the certificate message.
 * 
 *	\date Created on 28/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */
 
#ifdef MAKEFILE
#include "HandshakeMessages/Certificate.h"
#else
#include "Certificate.h"
#endif

/**
 * Make the certificate message for the server.
 * That message depends on the authentication algorithm hence we require the connection
 * parameters. The function also sets the certificate in the connection parameters for
 * further uses.
 *
 *	\param connection_parameters: connection parameters
 *	\return the certificate handshake message
 */
handshake_t * make_certificate(handshake_parameters_t *connection_parameters){

	// Initialize certificate message
	certificate_message_t *cert_message = NULL;

	// Make certificate message
	switch (connection_parameters->cipher_suite.au){
		case RSA_AU:
			cert_message = make_certificate_message("../certificates/serverRSA.pem");
			break;
		case DSS_AU:
			cert_message = make_certificate_message("../certificates/serverDSA.pem");
			break;
		case ECDSA_AU:
			cert_message = make_certificate_message("../certificates/serverECDSA.pem");
			break;
		default:
			printf("\nError in make_certificate_message");
			exit(-1);
	}

	// Insert certificate message into handshake packet
	handshake_t *certificate_h = malloc(sizeof(handshake_t));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));

	// Save parameters
	connection_parameters->server_certificate = cert_message->X509_certificate;
	connection_parameters->server_certificate->references+=1;

	// Clean up
	free_certificate_message(cert_message);

	return certificate_h;
}

/**
 * Given the certificate file name create a certificate message struct
 * that encapsulate it.
 *
 *	\param cert_file_name: certificate file name including path
 *	\return the certificate message struct
 */
certificate_message_t *make_certificate_message(char *cert_file_name){

	certificate_message_t *result = malloc(sizeof(certificate_message_t));
	result->cert_length = 0;
	result->X509_certificate = NULL;
	X509 *x=NULL;
	FILE *fp = fopen(cert_file_name, "r");

	if (!fp) {
		fprintf(stderr, "\nUnable to open %s\n", cert_file_name);
		exit(-1);
	}

	x = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!x) {
		fprintf(stderr, "\nUnable to parse certificate in: %s\n", cert_file_name);
		fclose(fp);
		exit(-1);
	}

	result->X509_certificate = x;
	fclose(fp);

	int raw_certificate_len = i2d_X509(result->X509_certificate, NULL);
	result->cert_length += (raw_certificate_len+3); // length of the certificate plus the length field

	return result;
}

/**
 * Serialize the certificate message into a byte stream
 *
 *	\param cert: the message to serialize
 *	\param stream: the return stream. Must point to NULL
 *	\param len: the stream length
 */
void serialize_certificate_message(certificate_message_t *cert, unsigned char **stream, uint32_t *len){

	*len = cert->cert_length+3;
	*stream = malloc(sizeof(unsigned char)*(*len)); // 3 byte for the lenght of all certificate stream
	unsigned char *buff=*stream;

	// Copy length of the entire message
	uint32_t len_t = REV32(cert->cert_length)>>8;
	memcpy(buff, &len_t, 3);
	buff+=3;

	// Get certificate
	int raw_certificate_len;
	unsigned char *raw_cert, *p;
	raw_certificate_len = i2d_X509(cert->X509_certificate, NULL);
	raw_cert =malloc(sizeof(unsigned char)*raw_certificate_len);
	if (raw_cert == NULL){
		printf("\nError in serialize_certificate\n");
		exit(-1);
	}

	p = raw_cert;
	i2d_X509(cert->X509_certificate, &p);
	// Copy length
	len_t = REV32(raw_certificate_len)>>8;
	memcpy(buff, &len_t, 3);
	buff+=3;

	// Copy certificate
	memcpy(buff, raw_cert, raw_certificate_len);

	OPENSSL_free(raw_cert);
}

/**
 * De-serialize a byte stream into a certificate_message.
 *
 *	\param stream: the byte stream to de-serialize
 *	\param len: the byte stream length
 *	\return the certificate_message
 */
certificate_message_t *deserialize_certificate_message(unsigned char *stream, uint32_t len){

	certificate_message_t *result = malloc(sizeof(certificate_message_t));
	result->X509_certificate = NULL;
	result->cert_length = len - 3; // 3 byte are used for the lenght
	unsigned char *buff = stream;
	buff+=3; 
	// Copy length
	uint32_t len_t;
	memcpy(&len_t,buff, 3);
	len_t = REV32(len_t)>>8;
	buff+=3;
	// Copy certificate
	unsigned char *p;
	p=buff;
	// Build X509
	if(!d2i_X509(&result->X509_certificate, (const unsigned char **)&p, len_t)){
		fprintf(stderr, "\nError in deserialize_certificate\n");
		exit(-1);
	}

	return result;
}

/**
 * Dealloc memory of certificate_message
 * 
 *	\param cert: the certificate message to deallocate
 */
void free_certificate_message(certificate_message_t *cert){

	if(cert == NULL)
		return;

	X509_free(cert->X509_certificate);
	free(cert);
}
