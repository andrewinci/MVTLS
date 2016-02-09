/**
 *	SSL/TLS Project
 *	\file ServerClientHello.c
 *
 *	This file is used to manage the client/server hello message of the handshake protocol
 *
 *	\date Created on 24/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */


#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientHello.h"
#else
#include "ServerClientHello.h"
#endif

/**
 * Make a client hello message.
 * The function set the UNIX time stamp, random and the session, if given. 
 *
 * \param session: session id to recover
 * \return the handshake, it has to be deallocated
 */
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

/**
 * Serialize a server_hello struct into a byte stream.
 *
 *	\param hello: struct to serialize
 *	\param stream: a pointer to NULL. Will return the stream byte.
 *	\param streamLen: the return stream length
 *	\param mode: set SERVER_MODE for a server hello message, CLIENT_MODE for client hello message
 */
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

/**
 * De-serialize a byte stream into a server_client_hello struct.
 *
 *	\param stream: the stream to de-serialize.
 *	\param streamLen: the stream length
 *	\param mode: set SERVER_MODE for a server hello message, CLIENT_MODE for client hello message
 */
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

/**
 * Print details about the server/client hello
 *
 *	\param h: the server client struct to print
 */
void print_hello(server_client_hello_t *h){

	printf("\n TLS version: %04X\n",h->TLS_version);
	printf("\n UNIX time stamp: %d\n", h->random.UNIX_time);
	printf("\n Random bytes (28): ");
	for(int i=0;i<28;i++)
		printf("%02X ",h->random.random_bytes[i]);
	printf("\n Session id: ");
	for(int i=0; i < h->session_id.session_lenght; i++)
		printf("%02X ",h->session_id.session_id[i]);

	printf("\n Cipher suites: \n");
	for(int i=0;i<h->cipher_suite_len/2;i++)
		printf("  id: %04X name: %s\n", h->cipher_suites[i].cipher_id ,h->cipher_suites[i].name);
	printf(" \n No compression\n");
}

/**
 * Delloc memory of server_client_hello.
 * 
 *	\param h: the struct to deallocate
 */
void free_hello(server_client_hello_t *h){
	free(h->compression_methods.compression_id);
	free(h->cipher_suites);
	free(h->session_id.session_id);
	free(h);
}

			/****************** HANDSHAKE FUNCTIONS **************************/
/**
 * Given the client hello message the function makes the server hello.
 * It chooses a random cipher suite among those provided by the client.
 * The function also fills the random field using the time stamp and a random generator (OpenSSL)
 *
 *	\param connection_parameters: the connection parameters
 *	\param client_hello: the received client hello.
 *	\return the hello server handshake message
 */
handshake_t * make_server_hello(handshake_parameters_t *connection_parameters, server_client_hello_t *client_hello){

	// Initialize server hello (without SessionID)
	session_id_t *session= malloc(sizeof(session_id_t));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	server_client_hello_t *server_hello = make_hello(*session);
	server_hello->TLS_version = TLS1_2;

	// Choose and set cipher suite
	srand((int)time(NULL));
	int choosen_suite_num = rand()%(client_hello->cipher_suite_len/2);
	cipher_suite_t choosen_suite = get_cipher_suite_by_id(client_hello->cipher_suites[choosen_suite_num].cipher_id);

	server_hello->cipher_suite_len = 2;

	server_hello->cipher_suites = malloc(sizeof(cipher_suite_t));
	*(server_hello->cipher_suites) = choosen_suite;

	// Insert server hello into handshake packet
	handshake_t *server_hello_h = malloc(sizeof(handshake_t));
	server_hello_h->type = SERVER_HELLO;
	server_hello_h->message = NULL;
	server_hello_h->length = 0;
	serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);

	// Save parameters
	connection_parameters->cipher_suite = choosen_suite;
	memcpy(connection_parameters->server_random,&(server_hello->random.UNIX_time), 4);
	memcpy(connection_parameters->server_random+4, server_hello->random.random_bytes, 28);

	// Clean up
	free_hello(server_hello);
	free(session);

	return server_hello_h;
}

/**
 * Given an array of cipher suites, make a client hello message.
 * The function also fills the random field using the time stamp and a random generator (OpenSSL)
 *
 *	\param client_random: return the random set in the client hello
 *	\param cipher_suite_list: an array of cipher suites to add to the client hello
 *	\param cipher_suite_len: the number of cipher suites in the list
 *	\return the client hello handshake message
 */
handshake_t * make_client_hello(unsigned char *client_random, cipher_suite_t cipher_suite_list[], int cipher_suite_len){

	// Initialize client hello (without SessionID)
	session_id_t *session= malloc(sizeof(session_id_t));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	server_client_hello_t *client_hello = make_hello(*session);
	client_hello->TLS_version = TLS1_2;

	client_hello->cipher_suite_len = 2*cipher_suite_len;
	client_hello->cipher_suites = malloc(sizeof(cipher_suite_t)*cipher_suite_len);
	for(int i=0;i<cipher_suite_len;i++)
		client_hello->cipher_suites[i]=cipher_suite_list[i];

	// Insert client hello into handshake packet
	handshake_t *client_hello_h = malloc(sizeof(handshake_t));
	client_hello_h->type = CLIENT_HELLO;
	serialize_client_server_hello(client_hello, &(client_hello_h->message), &(client_hello_h->length), CLIENT_MODE);

	// Save parameters
	memcpy(client_random,&(client_hello->random.UNIX_time),4);
	memcpy(client_random+4,client_hello->random.random_bytes,28);

	// Clean up
	free(session);
	free_hello(client_hello);

	return client_hello_h;
}
