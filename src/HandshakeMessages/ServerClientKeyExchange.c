/**
 *	SSL/TLS Project
 *	\file ServerClientKeyExchange.c
 *
 *	This file contains functions to manage the server/client key exchange
 *	and respective structs.
 *
 *	\date Created on 06/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientKeyExchange.h"
#else
#include "ServerClientKeyExchange.h"
#endif
				/******* SERVER KEY EXCHANGE *******/
/**
 * Serialize a server key exchange message into a byte stream.
 * 
 *	\param server_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 *	\param kx: the key exchange method of the handshake
 */
void serialize_server_key_exchange(server_key_exchange_t *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx){

	unsigned char *result;
	uint16_t len;

	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = (dhe_server_key_exchange_t*)server_key_exchange;
		int pLen = BN_num_bytes(server_key_ex->p), gLen = BN_num_bytes(server_key_ex->g), pubKeyLen = BN_num_bytes(server_key_ex->pubKey);

		*streamLen = 2+pLen+2+gLen+2+pubKeyLen+2+2+server_key_ex->signature_length;
		result = malloc(sizeof(unsigned char)*(*streamLen));
		*stream = result;

		pLen = REV16(pLen);
		memcpy(result, &pLen, 2);
		result+=2;
		len = BN_bn2bin(server_key_ex->p, result);
		result+=len;

		gLen = REV16(gLen);
		memcpy(result, &gLen, 2);
		result+=2;

		len = BN_bn2bin(server_key_ex->g, result);
		result+=len;

		pubKeyLen = REV16(pubKeyLen);
		memcpy(result, &pubKeyLen, 2);
		result+=2;

		len = BN_bn2bin(server_key_ex->pubKey, result);
		result+=len;

		// Add signature
		memcpy(result, &(server_key_ex->sign_hash_alg), 2);
		result+=2;

		len = server_key_ex->signature_length;
		len = REV16(len);
		memcpy(result, &len, 2);
		result+=2;

		memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
	}
	else if(kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = (ecdhe_server_key_exchange_t*)server_key_exchange;
		// Compute stream len
		// named_curve(1) curve_name(2) pub_key_len(1) pub_key(..) signature_alg(2) signature_len(2) siganture(..)
		*streamLen = 1 + 2 + 1 + BN_num_bytes(server_key_ex->pub_key) + 2 + 2 + server_key_ex->signature_length;

		result = malloc(sizeof(unsigned char)*(*streamLen));
		*stream = result;

		// Set named_curve mode
		*result = 0x03;
		result++;

		// Set curve name
		uint16_t curve_name = server_key_ex->named_curve;
		curve_name = REV16(curve_name);
		memcpy(result, &curve_name, sizeof(uint16_t));
		result+=2;

		// Convert and set public key
		*result = BN_num_bytes(server_key_ex->pub_key);
		result++;

		BN_bn2bin(server_key_ex->pub_key, result);
		result+=BN_num_bytes(server_key_ex->pub_key);

		// Add signature
		memcpy(result, &(server_key_ex->sign_hash_alg), 2);
		result+=2;

		len = REV16(server_key_ex->signature_length);
		memcpy(result, &len, 2);
		result+=2;

		memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
	}
}

/**
 * De-serialize a server key exchange byte stream message into the appropriate 
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\param kx: the key exchange method of the handshake
 *	\return the de-serialized server_key_exchange message.
 */
server_key_exchange_t *deserialize_server_key_exchange(unsigned char *message, uint32_t message_len, key_exchange_algorithm kx){
	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = malloc(sizeof(dhe_server_key_exchange_t));
		uint16_t len;

		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->p = BN_bin2bn(message, len, NULL);
		message+=len;
		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->g = BN_bin2bn(message, len, NULL);
		message+=len;
		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->pubKey = BN_bin2bn(message, len, NULL);
		message+=len;

		memcpy(&(server_key_ex->sign_hash_alg), message, 2);
		message+=2;

		memcpy(&(server_key_ex->signature_length), message, 2);
		message+=2;

		server_key_ex->signature_length = REV16(server_key_ex->signature_length);
		server_key_ex->signature = malloc(sizeof(unsigned char)*server_key_ex->signature_length);
		memcpy(server_key_ex->signature, message, server_key_ex->signature_length);

		return (server_key_exchange_t*)server_key_ex;
	}
	else if (kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = malloc(sizeof(ecdhe_server_key_exchange_t));
		message++; // we already know that it is 0x03 for named_curve
		uint16_t curve_name;
		memcpy(&curve_name, message, sizeof(char)*2);
		server_key_ex->named_curve = REV16(curve_name);
		message+=2;

		uint8_t pubkey_len = *message;
		message++;
		server_key_ex->pub_key = BN_bin2bn(message, pubkey_len, NULL);
		message+=pubkey_len;

		memcpy(&(server_key_ex->sign_hash_alg), message, 2);
		message+=2;

		memcpy(&(server_key_ex->signature_length), message, 2);
		message+=2;

		server_key_ex->signature_length = REV16(server_key_ex->signature_length);
		server_key_ex->signature = malloc(sizeof(unsigned char)*server_key_ex->signature_length);
		memcpy(server_key_ex->signature, message, server_key_ex->signature_length);

		return (server_key_exchange_t*)server_key_ex;
	}

	return NULL;
}

/**
 * Print details about the server key exchange message
 *
 *	\param server_key_exchange: the message to print
 *	\param kx: the key exchange method of the handshake
 */
void print_server_key_exchange(server_key_exchange_t *server_key_exchange, key_exchange_algorithm kx){

	char *pubkey_char = NULL;

	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = (dhe_server_key_exchange_t *) server_key_exchange;
		// Extract p, g, pubkey
		char *p = NULL;
		p = BN_bn2hex(server_key_ex->p);

		char *g = NULL;
		g = BN_bn2hex(server_key_ex->g);

		pubkey_char = BN_bn2hex(server_key_ex->pubKey);

		printf("** DHE parameters **\n");
		printf(" p: %s",p);
		printf("\n g: %s",g);
		printf("\n Public key: %s",pubkey_char);

		printf("\n Signature hash algorithm: %04x", server_key_ex->sign_hash_alg);
		printf("\n Signature: ");
		for(int i =0;i<server_key_ex->signature_length; i++)
			printf("%02X ", server_key_ex->signature[i]);
		printf("\n");

		OPENSSL_free(p);
		OPENSSL_free(g);
	}
	else if (kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = (ecdhe_server_key_exchange_t *) server_key_exchange;

		pubkey_char = BN_bn2hex(server_key_ex->pub_key);

		printf("** ECDHE parameters **\n");
		printf(" Curve type: named_curve");
		printf("\n Named curve: %04X", server_key_ex->named_curve);
		printf("\n Public key: %s",pubkey_char);

		printf("\n Signature hash algorithm: %04x", server_key_ex->sign_hash_alg);
		printf("\n Signature: ");
		for(int i =0;i<server_key_ex->signature_length; i++)
			printf("%02X ", server_key_ex->signature[i]);
		printf("\n");
	}

	OPENSSL_free(pubkey_char);
}

/**
 * Dealloc memory of server key exchange.
 * 
 *	\param server_key_ex: the server key exchange message to deallocate
 *	\param kx: the key exchange method of the handshake
 */
void free_server_key_exchange(server_key_exchange_t *server_key_ex, key_exchange_algorithm kx){
	if(server_key_ex != NULL && kx == DHE_KX){
		dhe_server_key_exchange_t *params = (dhe_server_key_exchange_t*)server_key_ex;
		BN_free(params->g);
		BN_free(params->p);
		BN_free(params->pubKey);
		free(params->signature);
		free(params);
	}
	else if(server_key_ex != NULL && kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *params = (ecdhe_server_key_exchange_t*) server_key_ex;
		free(params->signature);
		BN_free(params->pub_key);
		free(server_key_ex);
	}
}
				/******* CLIENT KEY EXCHANGE *******/

/**
 * Serialize a client key exchange message into a byte stream.
 * 
 *	\param client_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 */
void serialize_client_key_exchange(client_key_exchange_t *client_key_exchange, unsigned char **stream, uint32_t *streamLen){
	// The first 2 message byte are the key length
	unsigned char *buff = malloc(sizeof(unsigned char)*(client_key_exchange->key_length+2));
	*stream = buff;
	// Add lenght
	uint16_t temp = REV16(client_key_exchange->key_length);
	memcpy(buff, &temp, 2);
	buff+=2;
	// Add key
	memcpy(buff, client_key_exchange->key, client_key_exchange->key_length);
	*streamLen=client_key_exchange->key_length+2;
}

/**
 * De-serialize a client key exchange byte stream message into the appropriate 
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\return the de-serialized client key exchange message
 */
client_key_exchange_t *deserialize_client_key_exchange(unsigned char *message, uint32_t message_len){
	client_key_exchange_t *rsa_server_key_ex = malloc(sizeof(client_key_exchange_t));
	memcpy(&(rsa_server_key_ex->key_length), message, 2);
	message+=2;

	rsa_server_key_ex->key_length = REV16(rsa_server_key_ex->key_length);

	unsigned char *buff = malloc(sizeof(unsigned char)*rsa_server_key_ex->key_length);
	rsa_server_key_ex->key = buff;
	memcpy(buff, message, rsa_server_key_ex->key_length);

	return rsa_server_key_ex;
}

/**
 * Print details about the client key exchange message
 *
 *	\param client_key_exchange: the message to print
 */
void print_client_key_exchange(client_key_exchange_t *client_key_exchange){
	printf(" Public key: ");
	for(int i = 0; i<client_key_exchange->key_length; i++)
		printf("%02X ",client_key_exchange->key[i]);
	printf("\n");
}

/**
 * Dealloc memory of client key exchange.
 * 
 *	\param client_key_exchange: the client key exchange message to deallocate
 */
void free_client_key_exchange(client_key_exchange_t *client_key_exchange){
	free(client_key_exchange->key);
	free(client_key_exchange);
}
