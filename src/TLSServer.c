//
//  SSL/TLS Project
//  TLSServer.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "TLS.h"

handshake * make_server_hello(TLS_parameters *TLS_param, handshake_hello *client_hello){

	// Initialize  server hello (without SessionID)
	session_id *session= malloc(sizeof(session_id));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	handshake_hello *server_hello = make_hello(*session);
	server_hello->TLS_version = TLS1_2;

	// Choose and set cipher suite
	server_hello->cipher_suites = malloc(sizeof(cipher_suite_t));
	srand(time(NULL));
	int choosen_suite_num = rand()%(client_hello->cipher_suite_len/2); // Specify the number of supported cipher suite
	cipher_suite_t choosen_suite = get_cipher_suite( client_hello->cipher_suites[choosen_suite_num].cipher_id );

	server_hello->cipher_suites = malloc(sizeof(cipher_suite_t));
	*(server_hello->cipher_suites) = choosen_suite;

	// Insert server hello into handshake packet
	handshake *server_hello_h = malloc(sizeof(handshake));
	server_hello_h->type = SERVER_HELLO;
	server_hello_h->message = NULL;
	server_hello_h->length = 0;
	serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);

	// Save parameters
	TLS_param->cipher_suite = choosen_suite;
	memcpy(TLS_param->server_random,&(server_hello->random.UNIX_time), 4);
	memcpy(TLS_param->server_random+4, server_hello->random.random_bytes, 28);

	// Clean up
	free_hello(server_hello);
	free(session);

	return server_hello_h;
}

handshake * make_certificate(TLS_parameters *TLS_param){

	// Initialize certificate message
	certificate_message *cert_message = NULL;

	// Make certificate message
	switch (TLS_param->cipher_suite.au){
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
			break;
	}

	// Insert certificate message into handshake packet
	handshake *certificate_h = malloc(sizeof(handshake));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));

	// Save parameters
	TLS_param->server_certificate = cert_message->X509_certificate;
	TLS_param->server_certificate->references+=1;

	// Clean up
	free_certificate_message(cert_message);

	return certificate_h;
}

handshake * make_server_key_exchange(TLS_parameters *TLS_param){

	// Initialize server key exchange
	void *server_key_ex;

	// Make  server key exchange packet
	switch (TLS_param->cipher_suite.kx){
		case DHE_KX:
			server_key_ex = (DHE_server_key_exchange *)make_DHE_server_key_exchange(TLS_param);
			break;
		case ECDHE_KX:
			server_key_ex = (ECDHE_server_key_exchange *)make_ECDHE_server_key_exchange(TLS_param);
			break;
		default:
			printf("\nError in make_server_key_exchange\n");
			break;
	}

	// Insert server key exchange into handshake packet
	handshake *server_key_ex_h = malloc(sizeof(handshake));
	server_key_ex_h->type = SERVER_KEY_EXCHANGE;
	serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, TLS_param->cipher_suite.kx);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;

	return server_key_ex_h;
}

DHE_server_key_exchange * make_DHE_server_key_exchange(TLS_parameters *TLS_param){

	// Diffie-Hellman server key exchange
	// Generate ephemeral Diffie-Hellman parameters
	DH *privkey;
	int codes;
	if((privkey = DH_new()) == NULL)
		printf("\nError in DH_new\n");
	if(DH_generate_parameters_ex(privkey, 1024, DH_GENERATOR_2 , NULL) != 1)
		printf("\nError in DH_generate_parameters\n");
	if(DH_check(privkey, &codes) != 1)
		printf("\nError in DH_check\n");
	if(codes != 0)
		printf("\nDH_check failed\n");
	// Generate the public and private keys pair
	if(DH_generate_key(privkey) != 1)
		printf("Error in DH_generate_key\n");

	// Set server key exchange parameters
	DHE_server_key_exchange *server_key_ex = malloc(sizeof(DHE_server_key_exchange));
	server_key_ex->g = BN_dup(privkey->g);
	server_key_ex->p = BN_dup(privkey->p);
	server_key_ex->pubKey = BN_dup(privkey->pub_key);

	// Set hash algorithm and authentication
	server_key_ex->sign_hash_alg = TLS_param->cipher_suite.hash+(TLS_param->cipher_suite.au<<8); // 0x0106 // Already rotated

	// Add signature
	sign_DHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;
	TLS_param->private_key = BN_dup(privkey->priv_key);

	// Clean up
	DH_free(privkey);

	return server_key_ex;
}

ECDHE_server_key_exchange * make_ECDHE_server_key_exchange(TLS_parameters *TLS_param){

	// Elliptic cruve Diffie-Hellman server key exchange
	// Generate ephemeral Diffie-Hellman parameters
	EC_KEY *key;
	uint16_t curve_name = NID_secp256k1;
	// Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve
	if((key = EC_KEY_new_by_curve_name(curve_name)) == NULL)
		printf("\nError setting  EC parameters\n");
	// Generate the private and public keys
	if(EC_KEY_generate_key(key) != 1)
		printf("\nError in generate EC keys\n");

	// Set server key exchange parameters
	ECDHE_server_key_exchange *server_key_ex = malloc(sizeof(ECDHE_server_key_exchange));
	server_key_ex->named_curve = curve_name;
	server_key_ex->pub_key = BN_new();
	EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, server_key_ex->pub_key, NULL);

	// Set hash algorithm and authentication
	server_key_ex->sign_hash_alg = TLS_param->cipher_suite.hash+(TLS_param->cipher_suite.au<<8); // Already rotated

	// Add signature
	sign_ECDHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;
	TLS_param->private_key = BN_dup(EC_KEY_get0_private_key(key));

	// Clean up
	EC_KEY_free(key);

	return server_key_ex;
}

handshake * make_server_hello_done() {

	// Make and insert server done into handshake packet
	handshake *server_hello_done = malloc(sizeof(handshake));
	server_hello_done->type = SERVER_DONE;
	server_hello_done->length =0x00;
	server_hello_done->message = NULL;

	return server_hello_done;
}
