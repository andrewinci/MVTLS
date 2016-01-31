//
//  SSL/TLS Project
//  Certificate.h
//
//  Created on 28/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
//  The certificate message is divided in this way:
//  lenght of all message: 3 byte
//  foreach certificate:
//  length of the current certificate : 3 byte
//  certificate...
//
//  In total we have 3 + 3*NumCertificate + the lenght of all certificate

#ifndef Certificate_h
#define Certificate_h

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/pem.h>

#include "TLSConstants.h"

#endif /* Certificate_h */

typedef struct{
	uint32_t cert_length; // only 3 byte are used
	X509 *X509_certificate;
}certificate_message_t;

/*
 * Create a certificate message from a list of certificate
 * cert_files_name  : list of path for certificates in DER format
 * list_size        : the number of path in cert_files_name
 *  return a certificate_message ready for serialize and send
 */
certificate_message_t *make_certificate_message(char *cert_file_name);

/*
 * Serialization of the packet like always
 */
void serialize_certificate_message(certificate_message_t *cert, unsigned char **stream, uint32_t *len);

/*
 * Deserialization
 */
certificate_message_t *deserialize_certificate_message(unsigned char *stream, uint32_t len);

/*
 * Free the allocation
 */
void free_certificate_message(certificate_message_t *cert);
