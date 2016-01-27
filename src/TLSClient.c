//
//  SSL/TLS Project
//  SSLClient.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "TLS.h"

/* Utils functions */

void backup_handshake(TLS_parameters *TLS_param, handshake *h){

	// Initialize
	unsigned char *temp_message = NULL;
	uint32_t temp_message_len = 0;

	// Allocate memory
	serialize_handshake(h, &temp_message, &temp_message_len);
	if(TLS_param->handshake_messages == NULL)
		TLS_param->handshake_messages = malloc(TLS_param->handshake_messages_len+temp_message_len);
	else
		TLS_param->handshake_messages = realloc(TLS_param->handshake_messages, TLS_param->handshake_messages_len+temp_message_len);

	// Copy message
	memcpy(TLS_param->handshake_messages+TLS_param->handshake_messages_len, temp_message, temp_message_len);
	TLS_param->handshake_messages_len += temp_message_len;

	// Clean up
	free(temp_message);
}

/* Functions to send messages */

handshake * make_client_hello(unsigned char *client_random){
	// Initialize client hello (without SessionID)
	session_id *session= malloc(sizeof(session_id));    
	session->session_lenght =0x00;
	session->session_id = NULL;
	handshake_hello *client_hello = make_hello(*session);
	client_hello->TLS_version = TLS1_2;

	// Add ciphersuites
	int supported = 1;
	client_hello->cipher_suite_len = supported*2;
	client_hello->cipher_suites = malloc(sizeof(cipher_suite_t)*supported);
	uint16_t supported_id[] = {
		0xC006,		// ECDHE_ECDSA
		//0xC010,		// ECDHE_RSA
		//0x0011,		// DHE_DSS
		//0x0014,		// DHE_RSA
		//0x0001		// RSA
		};
	for(int i=0;i<supported;i++)
		client_hello->cipher_suites[i]=get_cipher_suite(supported_id[i]);

	// Insert server hello into handshake packet
	handshake *client_hello_h = malloc(sizeof(handshake));
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

handshake * make_client_key_exchange(TLS_parameters *TLS_param, uint16_t key_ex_alg){

	// Initialize handshake packet and client key exchange message
	handshake *client_key_exchange_h = malloc(sizeof(handshake));
	client_key_exchange_h->type = CLIENT_KEY_EXCHANGE;
	client_key_exchange *client_key_ex = malloc(sizeof(client_key_exchange));

	switch (TLS_param->cipher_suite.kx){
		case RSA_KX:
			make_RSA_client_key_exchange(client_key_ex, TLS_param);
			break;
		case DHE_KX:
			make_DHE_client_key_exchange(client_key_ex, TLS_param);
			break;
		case ECDHE_KX:
			make_ECDHE_client_key_exchange(client_key_ex, TLS_param);
			break;
		default:
			printf("\nError in make_client_key_exchange\n");
			break;
	}

	serialize_client_key_exchange(client_key_ex, &(client_key_exchange_h->message), (&client_key_exchange_h->length));

	//Clean up
	free(client_key_ex->key);
	free(client_key_ex);

	return client_key_exchange_h;
}

void make_RSA_client_key_exchange(client_key_exchange *client_key_ex, TLS_parameters *TLS_param){

	// Initialize pre master key
	int pre_master_key_len = 58;
	unsigned char *pre_master_key = calloc(pre_master_key_len, 1);

	uint16_t temp = REV16(TLS_param->tls_version);
	memcpy(pre_master_key, &temp, 2);

	// Copy random
	RAND_pseudo_bytes(pre_master_key+2, 46);
	unsigned char seed[64];
	memcpy(seed, TLS_param->client_random, 32);
	memcpy(seed+32, TLS_param->server_random, 32);

	// Set hash function
	const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);
	TLS_param->master_secret_len = 48;

	// Compute and set pre master key
	PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);

	// Initialize and set RSA parameters from certificate
	EVP_PKEY *pubkey = NULL;
	RSA *rsa = NULL;

	pubkey = X509_get_pubkey(TLS_param->server_certificate);
	rsa = EVP_PKEY_get1_RSA(pubkey);

	// Encrypt pre master key
	unsigned char *pre_master_key_enc = malloc(256);
	int pre_master_key_enc_len = 0;
	pre_master_key_enc_len = RSA_public_encrypt(pre_master_key_len, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);

	// Set parameters in client key exchange packet
	client_key_ex->key = pre_master_key_enc;
	client_key_ex->key_length = pre_master_key_enc_len;

	// Clean up
	EVP_PKEY_free(pubkey);
	RSA_free(rsa);
	free(pre_master_key);
}

void make_DHE_client_key_exchange(client_key_exchange *client_key_ex, TLS_parameters *TLS_param){

	// Set server key exchange type
	DHE_server_key_exchange *server_key_exchange = (DHE_server_key_exchange*)TLS_param->server_key_ex;

	// Verify signature
	if(verify_DHE_server_key_ex_sign(TLS_param->server_certificate, TLS_param->client_random, TLS_param->server_random, server_key_exchange,TLS_param->cipher_suite.au) == 0){
		printf("\nError in make_DHE_client_key_exchange, signature not valid\n");
		exit(-1);
	}
	printf("Signature is valid");

	// Initialize and set Diffie-Hellman parameters
	DH *privkey = DH_new();
	privkey->g = server_key_exchange->g;
	privkey->p = server_key_exchange->p;
	if(DH_generate_key(privkey) != 1)
		printf("Error in DH_generate_key\n");

	// Initialize pre master key
	unsigned char *pre_master_key = malloc(DH_size(privkey));
	int pre_master_key_len = 0;
	pre_master_key_len = DH_compute_key(pre_master_key, server_key_exchange->pubKey, privkey);

	// Copy random
	unsigned char seed[64];
	memcpy(seed, TLS_param->client_random, 32);
	memcpy(seed+32, TLS_param->server_random, 32);

	// Set hash function
	const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);

	// Initialize and comput pre master key
	TLS_param->master_secret_len = 48;
	PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);

	// Set client key exchange parameters
	client_key_ex->key_length = BN_num_bytes(privkey->pub_key);
	client_key_ex->key = malloc(sizeof(unsigned char)*client_key_ex->key_length);
	BN_bn2bin(privkey->pub_key, client_key_ex->key);

	// Clean up
	DH_free(privkey);
	free(pre_master_key);
}

void make_ECDHE_client_key_exchange(client_key_exchange *client_key_ex, TLS_parameters *TLS_param){

	// Set server key exchange algorithm
	ECDHE_server_key_exchange *server_key_exchange = (ECDHE_server_key_exchange * )TLS_param->server_key_ex;

	// Verify signature
	if(verify_ECDHE_server_key_ex_sign(TLS_param->server_certificate, TLS_param->client_random, TLS_param->server_random, server_key_exchange,TLS_param->cipher_suite.au)<1){
		printf("\nError in make_ECDHE_client_key_exchange, signature not valid\n");
		exit(-1);
	}
	printf("Signature is valid");

	// Initialize and set elliptic curve Diffie-Hellman parameters
	EC_KEY *key = EC_KEY_new_by_curve_name(server_key_exchange->named_curve);
	if(EC_KEY_generate_key(key) != 1)
		printf("\nError in make_ECDHE_client_key_exchange, EC_KEY_generate\n");
	EC_POINT *pub_key_point = EC_POINT_bn2point(EC_KEY_get0_group(key), server_key_exchange->pub_key, NULL, NULL);

	// Initialize pre master secret
	int field_size, pre_master_len;
	unsigned char *pre_master;

	// Calculate size of buffer for shared secret
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	pre_master_len = (field_size+7)/8;
	// Allocate memory for shared secret 
	pre_master = malloc(sizeof(unsigned char)*pre_master_len);
	// Derive shared secret 
	ECDH_compute_key(pre_master, pre_master_len, pub_key_point, key, NULL);

	// Copy random
	unsigned char seed[64];
	memcpy(seed, TLS_param->client_random, 32);
	memcpy(seed+32, TLS_param->server_random, 32);

	// Get hash function
	const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);

	// Initialize and compute pre master secret
	TLS_param->master_secret_len = 48;
	PRF(hash_function, pre_master, pre_master_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);

	// Compute client key exchange parameters
	BIGNUM *pub_key = BN_new();
	EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, pub_key, NULL);

	// Set client key exchange parameters
	client_key_ex->key_length = BN_num_bytes(pub_key);
	client_key_ex->key = malloc(sizeof(unsigned char)*client_key_ex->key_length);
	BN_bn2bin(pub_key, client_key_ex->key);

	// Clean up
	BN_free(pub_key);
	EC_POINT_free(pub_key_point);
	EC_KEY_free(key);
	free(pre_master);
}

record_t * make_change_cipher_spec() {

	//make and send change cipher spec message
	record_t *change_cipher_spec_message = malloc(sizeof(record_t));
	change_cipher_spec_message->type = CHANGE_CIPHER_SPEC;
	change_cipher_spec_message->version = TLS1_2;
	change_cipher_spec_message->length = 0x01;
	change_cipher_spec_message->message = malloc(1);
	*(change_cipher_spec_message->message) = 0x01;

	return change_cipher_spec_message;
}

handshake * make_finished_message(TLS_parameters *TLS_param ) {

	// Initialize finished
	handshake *finished_h = malloc(sizeof(handshake));
	finished_h->type = FINISHED;

	// Compute hashes of handshake messages
	const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash_function, NULL);
	EVP_DigestUpdate(mdctx, TLS_param->handshake_messages, TLS_param->handshake_messages_len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);

	// Set finished message
	unsigned char *finished_message = NULL;
	int finished_message_len = 12;
	PRF(hash_function, TLS_param->master_secret, TLS_param->master_secret_len, "client finished", md_value, md_len, finished_message_len, &finished_message);
	finished_h->length = finished_message_len;
	finished_h->message = finished_message;

	return finished_h;
}
