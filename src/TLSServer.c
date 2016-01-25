//
//  SSL/TLS Project
//  TLSServer.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "TLS.h"

/*
 * Choose a cipher suite, make server_hello
 * client_hello : client hello message received from client
 */
handshake * make_server_hello(TLS_parameters *TLS_param, handshake_hello *client_hello){
	// Make server_hello (without SessionID)
	session_id *session=  malloc(sizeof(session_id));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	handshake_hello *server_hello = make_hello(*session);
	server_hello->TLS_version = TLS1_2;

	// Choose a cipher suite
	free(server_hello->cipher_suites.cipher_id);
	server_hello->cipher_suites.length = 0x02;
	server_hello->cipher_suites.cipher_id = malloc(2);
	int choosen_suite = 6; // Specify the number of supported cipher suites
	*(server_hello->cipher_suites.cipher_id) = client_hello->cipher_suites.cipher_id[choosen_suite];
	TLS_param->cipher_suite = *(server_hello->cipher_suites.cipher_id);

	// Copy server's random
	memcpy(TLS_param->server_random, &(server_hello->random.UNIX_time), 4);
	memcpy(TLS_param->server_random+4, server_hello->random.random_bytes, 28);

	// Make server_hello
	handshake *server_hello_h = malloc(sizeof(handshake));
	server_hello_h->type = SERVER_HELLO;
	server_hello_h->message = NULL;
	server_hello_h->length = 0;
	serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);

	// Clean up
	free_hello(server_hello);
	free(session);

	return server_hello_h;
}

handshake * make_certificate(TLS_parameters *TLS_param){
	// Make certificate
	certificate_message *cert_message = make_certificate_message("../certificates/server.pem");

	handshake *certificate_h = malloc(sizeof(handshake));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));

	// Clean up
	free_certificate_message(cert_message);

	return certificate_h;
}

handshake * make_server_key_exchange(TLS_parameters *TLS_param){

	handshake *server_key_ex_h = malloc(sizeof(handshake));
	server_key_ex_h->type = SERVER_KEY_EXCHANGE;

	void *server_key_ex;
	uint16_t kx = get_kx_algorithm(TLS_param->cipher_suite);
	switch (kx){
	case DHE_RSA_KX:
		// Diffie-Hellman server_key_exchange
		server_key_ex = make_DHE_server_key_ex(TLS_param);
		break;
	case ECDHE_RSA_KX:
		// Diffie-Hellman over elliptic curve server_key_exchange
		server_key_ex = make_ECDHE_server_key_ex(TLS_param);
		break;
	default:
		printf("\nError in make_server_key_exchange\n");
		exit(-1);
	}

	// Insert server_key_ex into handshake
	serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, kx);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;

	return server_key_ex_h;
}

DHE_server_key * make_DHE_server_key_ex(TLS_parameters *TLS_param){
	// Initialize
	DH *privkey;
	int codes;

	// Generate ephemeral Diffie-Hellman parameters
	if((privkey = DH_new()) == NULL){
		printf("\nError in DH_new\n");
		exit(-1);
	}
	if(DH_generate_parameters_ex(privkey, 100, DH_GENERATOR_2 , NULL) != 1){
		printf("\nError in generate_parameter_ex\n");
		exit(-1);
	}   
	if(DH_check(privkey, &codes) != 1){
		printf("\nError in DH_check\n");
		exit(-1);
	}
	if(codes != 0){
		printf("\nDH_check failed\n");
		exit(-1);
	}

	// Generate the public and private keys pair
	if(DH_generate_key(privkey) != 1){
		printf("\nError in DH_generate_key\n");
		exit(-1);
	}

	// Make DH_server_key
	DHE_server_key *DHE_server_key = malloc(sizeof(DHE_server_key));
	DHE_server_key->g = BN_new();
	DHE_server_key->p = BN_new();
	DHE_server_key->pubKey = BN_new();
	// Copy DH parameters in the message struct
	if(BN_copy(DHE_server_key->g, privkey->g) == NULL)
		printf("\nError in copy DH parameters\n");
	if(BN_copy(DHE_server_key->p, privkey->p) == NULL)
		printf("\nError in copy DH parameters\n");
	if(BN_copy(DHE_server_key->pubKey, privkey->pub_key) == NULL)
		printf("\nError in copy DH parameters\n");

	DHE_server_key->sign_hash_alg = 0x0106; // Already rotated

	// Add RSA signature
	sign_DHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, DHE_server_key);

	// Save private DH key
	TLS_param->private_key = BN_new();
	BN_copy(TLS_param->private_key, privkey->priv_key);
}

ECDHE_server_key * make_ECDHE_server_key_ex(TLS_parameters *TLS_param){
	EC_KEY *key, *peerkey;
	int field_size;
	unsigned char *secret;
	int *secret_len;

	// Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve 
	if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)))
	printf("\nError setting  EC parameters\n");

	// Generate the private and public key
	if(1 != EC_KEY_generate_key(key))
	printf("\nError in generate EC keys\n");

	// Get the peer's public key, and provide the peer with our public key
	// how this is done will be specific to your circumstances
	//peerkey = get_peerkey_low(key);

	// Calculate the size of the buffer for the shared secret
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	*secret_len = (field_size+7)/8;

	// Allocate memory for the shared secret
	if(NULL == (secret = OPENSSL_malloc(*secret_len)))
	printf("\nErrror openssl malloc EC\n");
	// Derive the shared secret
	*secret_len = ECDH_compute_key(secret, *secret_len, EC_KEY_get0_public_key(peerkey), key, NULL);

	// Clean up
	EC_KEY_free(key);
	EC_KEY_free(peerkey);

	if(*secret_len <= 0){
		OPENSSL_free(secret);
		exit(-1);
	}
}

handshake * make_server_hello_done() {
	// Make server_hello_done
	handshake *server_hello_done = malloc(sizeof(handshake));
	server_hello_done->type = SERVER_DONE;
	server_hello_done->length =0x00;
	server_hello_done->message = NULL;
	return server_hello_done;
}
