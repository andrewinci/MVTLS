//
//  SSL/TLS Project
//  serverClientHello.h
//
//  Created on 24/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientHello.h"
#else
#include "ServerClientHello.h"
#endif

server_client_hello_t *make_hello(session_id_t session){

	server_client_hello_t *hello = malloc(sizeof(server_client_hello_t));

	// Compression method is setted to null by default
	hello->compression_methods.length = 0x01;
	hello->compression_methods.compression_id = 0x00;

	// Add random
	hello->random.UNIX_time = (uint32_t)time(NULL);
	uint8_t *random_stream = malloc(sizeof(uint8_t)*28);
	RAND_pseudo_bytes(random_stream, 28);

	for(int i=0;i<28;i++)
		hello->random.random_bytes[i] = *(random_stream+i);
	free(random_stream);

	hello->session_id = session;

	return hello;
}

void serialize_client_server_hello(server_client_hello_t *hello, unsigned char **stream, uint32_t *streamLen, channel_mode mode){

	// Compute the lenght
	if(mode == CLIENT_MODE)
		*streamLen = 2 + hello->cipher_suite_len + 2 + hello->compression_methods.length + 1 + 32 + hello->session_id.session_lenght + 1;
	else
		*streamLen = 2 + 2 + 1 + 32 + hello->session_id.session_lenght + 1;

	*stream = malloc(sizeof(unsigned char)*(*streamLen));
	unsigned char *buff = *stream;

	// Serialize TLS Version
	uint16_t TLS_version = REV16(hello->TLS_version);
	memcpy(buff, &TLS_version,2);
	buff+=2;

	// Serialize random
	random_data_t rdata = hello->random;

	rdata.UNIX_time = REV32(rdata.UNIX_time);
	memcpy(buff, &(rdata.UNIX_time), 4);
	buff+=4;

	memcpy(buff, rdata.random_bytes, 28);
	buff+=28;

	// Serialize session id
	session_id_t session = hello->session_id;

	memcpy(buff, &session.session_lenght, 1);
	buff++;

	memcpy(buff, session.session_id, session.session_lenght);
	buff+=session.session_lenght;

	// Serialize cipher suite
	if(mode == SERVER_MODE){
		//ServerHello
		uint16_t cipher_id = REV16(hello->cipher_suites[0].cipher_id);
		memcpy(buff, &cipher_id, 2); // only one cipher suite has to be in the message
		buff+=2;
	}
	else{
		//ClientHello
		uint16_t cipher_suite_len = REV16(hello->cipher_suite_len);
		memcpy(buff, &cipher_suite_len, 2);
		buff+=2;
		uint16_t temp;
		for(int i=0;i<hello->cipher_suite_len/2;i++){
			temp = REV16(hello->cipher_suites[i].cipher_id);
			memcpy(buff, &temp, 2);
			buff+=2;
		}
	}

	// Serialize compression method
	if(mode == SERVER_MODE)
		//ServerHello
		memcpy(buff, &hello->compression_methods.compression_id,1);
	else{
		//ClientHello
		memcpy(buff, &hello->compression_methods.length, 1);
		buff++;
		memcpy(buff, &hello->compression_methods.compression_id, 1);
	}
}

server_client_hello_t *deserialize_client_server_hello(unsigned char *stream, uint32_t streamLen, channel_mode mode){

	server_client_hello_t *result = malloc(sizeof(server_client_hello_t));

	// Deserialize TLSversion
	uint16_t TLS_version;
	memcpy(&TLS_version, stream,2);
	result->TLS_version = REV16(TLS_version);
	stream+=2;

	// Deserialize random
	random_data_t rdata;

	memcpy(&rdata.UNIX_time, stream, 4);
	rdata.UNIX_time = REV32(rdata.UNIX_time);
	stream+=4;

	memcpy(rdata.random_bytes, stream, 28);
	stream+=28;

	result->random = rdata;

	// Deserialize session id
	session_id_t session;

	session.session_lenght = *stream;
	stream++;

	session.session_id = malloc(sizeof(unsigned char)*session.session_lenght);
	memcpy(session.session_id, stream, session.session_lenght);
	stream+=session.session_lenght;

	result -> session_id = session;

	if(mode == SERVER_MODE){
		//ServerHello
		// Extract cipher suite
		uint16_t cipher_id = 0;
		memcpy(&cipher_id, stream, 2); // only one cipher suite has to be in the message
		cipher_id = REV16(cipher_id);
		result->cipher_suite_len = 0x0002;
		result->cipher_suites = malloc(sizeof(cipher_suite_t));
		result->cipher_suites[0] = get_cipher_suite_by_id(cipher_id);
		stream+=2;
	}
	else{
		//ClientHello
		uint16_t ciphers_len = 0;
		memcpy(&ciphers_len, stream, 2);
		ciphers_len = REV16(ciphers_len);
		result->cipher_suite_len = ciphers_len;
		stream+=2;
		result->cipher_suites = malloc(sizeof(cipher_suite_t)*(ciphers_len/2));
		for(int i=0;i<ciphers_len/2;i++){
			uint16_t cipher_id = 0;
			memcpy(&cipher_id, stream, 2);
			cipher_id = REV16(cipher_id);
			// Getting cipher_suite for each id
			cipher_suite_t temp = get_cipher_suite_by_id(cipher_id);
			memcpy(result->cipher_suites+i, &temp, sizeof(cipher_suite_t));
			stream+=2;
		}
	}

	// Deserialize compression
	compression_methods_t cmethods;

	cmethods.length = *stream;
	stream++;
	if(cmethods.length>0){
		cmethods.compression_id = malloc(sizeof(uint8_t)*cmethods.length);
		memcpy(cmethods.compression_id,stream,cmethods.length);
	}
    else
		cmethods.compression_id = NULL;

	result->compression_methods = cmethods;

	return result;
}

void print_hello(server_client_hello_t *h){
	printf("\nVersion : %d\n",h->TLS_version);
	printf("\nUNIX time stamp : %d\n", h->random.UNIX_time);
	printf("\nRandom bytes (28): ");
	for(int i=0;i<28;i++)
		printf("%02X ",h->random.random_bytes[i]);
	printf("\nSession id : ");
	for(int i=0; i < h->session_id.session_lenght; i++)
		printf("%02X ",h->session_id.session_id[i]);

	printf("\nCipher suites :\n");
	for(int i=0;i<h->cipher_suite_len/2;i++)
		printf("id: %04X name: %s\n", h->cipher_suites[i].cipher_id ,h->cipher_suites[i].name);
	printf(" \nNo compression (not implemented yet)\n");
}

void free_hello(server_client_hello_t *h){
	free(h->compression_methods.compression_id);
	free(h->cipher_suites);
	free(h->session_id.session_id);
	free(h);
}
