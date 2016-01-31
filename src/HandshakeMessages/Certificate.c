//
//  SSL/TLS Project
//  Certificate.c
//
//  Created on 28/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/Certificate.h"
#else
#include "Certificate.h"
#endif


certificate_message_t *make_certificate_message(char *cert_file_name){

	certificate_message_t *result = malloc(sizeof(certificate_message_t));
	result->cert_length = 0;
	result->X509_certificate = NULL;
	X509 *x=NULL;
	FILE *fp = fopen(cert_file_name, "r");

	if (!fp) {
		fprintf(stderr, "unable to open: %s\n", cert_file_name);
		exit(-1);
	}

	x = PEM_read_X509(fp, NULL, NULL, NULL);
	if (!x) {
		fprintf(stderr, "unable to parse certificate in: %s\n", cert_file_name);
		fclose(fp);
		exit(-1);
	}

	result->X509_certificate = x;
	fclose(fp);

	int raw_certificate_len = i2d_X509(result->X509_certificate, NULL);
	result->cert_length += (raw_certificate_len+3); // length of the certificate plus the length field

	return result;
}

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

	// Copy  certificate
	memcpy(buff, raw_cert, raw_certificate_len);

	OPENSSL_free(raw_cert);
}

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

void free_certificate_message(certificate_message_t *cert){
	if(cert == NULL)
		return;

	X509_free(cert->X509_certificate);
	free(cert);
}
