//
//  SSL/TLS Project
//  TLSServer.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "TLS.h"
/* Utils functions */

void backup_handshake(TLS_parameters_t *TLS_param, handshake_t *h){
    
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

                /*** SERVER ***/

handshake_t * make_server_hello(TLS_parameters_t *TLS_param, server_client_hello_t *client_hello){

	// Initialize  server hello (without SessionID)
	session_id_t *session= malloc(sizeof(session_id_t));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	server_client_hello_t *server_hello = make_hello(*session);
	server_hello->TLS_version = TLS1_2;

	// Choose and set cipher suite
	srand((int)time(NULL));
	int choosen_suite_num = rand()%(client_hello->cipher_suite_len/2); // Specify the number of supported cipher suite
	cipher_suite_t choosen_suite = get_cipher_suite_by_id( client_hello->cipher_suites[choosen_suite_num].cipher_id );

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
	TLS_param->cipher_suite = choosen_suite;
	memcpy(TLS_param->server_random,&(server_hello->random.UNIX_time), 4);
	memcpy(TLS_param->server_random+4, server_hello->random.random_bytes, 28);

	// Clean up
	free_hello(server_hello);
	free(session);

	return server_hello_h;
}

handshake_t * make_certificate(TLS_parameters_t *TLS_param){

	// Initialize certificate message
	certificate_message_t *cert_message = NULL;

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
            exit(-1);
			break;
	}

	// Insert certificate message into handshake packet
	handshake_t *certificate_h = malloc(sizeof(handshake_t));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));

	// Save parameters
	TLS_param->server_certificate = cert_message->X509_certificate;
	TLS_param->server_certificate->references+=1;

	// Clean up
	free_certificate_message(cert_message);

	return certificate_h;
}

handshake_t * make_server_key_exchange(TLS_parameters_t *TLS_param){

	// Initialize server key exchange
	void *server_key_ex = NULL;

	// Make  server key exchange packet
	switch (TLS_param->cipher_suite.kx){
		case DHE_KX:
			server_key_ex = (dhe_server_key_exchange_t *)make_DHE_server_key_exchange(TLS_param);
			break;
		case ECDHE_KX:
			server_key_ex = (ecdhe_server_key_exchange_t *)make_ECDHE_server_key_exchange(TLS_param);
			break;
		default:
			printf("\nError in make_server_key_exchange, key excahnge algorithm not recognized\n");
			break;
	}
    
    // Insert server key exchange into handshake packet
	handshake_t *server_key_ex_h = malloc(sizeof(handshake_t));
	server_key_ex_h->type = SERVER_KEY_EXCHANGE;
	serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, TLS_param->cipher_suite.kx);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;

	return server_key_ex_h;
}

dhe_server_key_exchange_t * make_DHE_server_key_exchange(TLS_parameters_t *TLS_param){

	// Diffie-Hellman server key exchange
	// Generate ephemeral Diffie-Hellman parameters
	DH *privkey;
	int codes;
	if((privkey = DH_new()) == NULL)
		printf("\nError in DH_new\n");
    if(DH_generate_parameters_ex(privkey, 512, DH_GENERATOR_2 , NULL) != 1){
		printf("\nError in DH_generate_parameters\n");
        exit(-1);
    }
	if(DH_check(privkey, &codes) != 1)
		printf("\nError in DH_check\n");
	if(codes != 0)
		printf("\nDH_check failed\n");
	// Generate the public and private keys pair
	if(DH_generate_key(privkey) != 1)
		printf("Error in DH_generate_key\n");

	// Set server key exchange parameters
	dhe_server_key_exchange_t *server_key_ex = malloc(sizeof(dhe_server_key_exchange_t));
	server_key_ex->g = BN_dup(privkey->g);
	server_key_ex->p = BN_dup(privkey->p);
	server_key_ex->pubKey = BN_dup(privkey->pub_key);
	
    // Add signature and set hash algorithm
	sign_DHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;
	TLS_param->private_key = BN_dup(privkey->priv_key);

	// Clean up
	DH_free(privkey);

	return server_key_ex;
}

ecdhe_server_key_exchange_t * make_ECDHE_server_key_exchange(TLS_parameters_t *TLS_param){

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
	ecdhe_server_key_exchange_t *server_key_ex = malloc(sizeof(ecdhe_server_key_exchange_t));
	server_key_ex->named_curve = curve_name;
	server_key_ex->pub_key = BN_new();
	EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, server_key_ex->pub_key, NULL);

	// Add signature
	sign_ECDHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);

	// Save parameters
	TLS_param->server_key_ex = server_key_ex;
	TLS_param->private_key = BN_dup(EC_KEY_get0_private_key(key));

	// Clean up
	EC_KEY_free(key);

	return server_key_ex;
}

handshake_t * make_server_hello_done() {

	// Make and insert server done into handshake packet
	handshake_t *server_hello_done = malloc(sizeof(handshake_t));
	server_hello_done->type = SERVER_DONE;
	server_hello_done->length = 0x00;
	server_hello_done->message = NULL;

	return server_hello_done;
}

                /*** CLIENT ***/

handshake_t * make_client_hello(unsigned char *client_random, cipher_suite_t cipher_suite_list[], int cipher_suite_len){
    // Initialize client hello (without SessionID)
    session_id_t *session= malloc(sizeof(session_id_t));
    session->session_lenght =0x00;
    session->session_id = NULL;
    server_client_hello_t *client_hello = make_hello(*session);
    client_hello->TLS_version = TLS1_2;
    
    client_hello->cipher_suite_len = 2*cipher_suite_len;
    client_hello->cipher_suites = malloc(sizeof(cipher_suite_t)*cipher_suite_len);
    for(int i=0;i<cipher_suite_len;i++)
        client_hello->cipher_suites[i]=cipher_suite_list[i];
    
    // Insert server hello into handshake packet
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

handshake_t * make_client_key_exchange(TLS_parameters_t *TLS_param, uint16_t key_ex_alg){
    
    // Initialize handshake packet and client key exchange message
    handshake_t *client_key_exchange_h = malloc(sizeof(handshake_t));
    client_key_exchange_h->type = CLIENT_KEY_EXCHANGE;
    client_key_exchange_t *client_key_exchange = malloc(sizeof(client_key_exchange_t));
    
    switch (TLS_param->cipher_suite.kx){
        case RSA_KX:
            make_RSA_client_key_exchange(client_key_exchange, TLS_param);
            break;
        case DHE_KX:
            make_DHE_client_key_exchange(client_key_exchange, TLS_param);
            break;
        case ECDHE_KX:
            make_ECDHE_client_key_exchange(client_key_exchange, TLS_param);
            break;
        default:
            printf("\nError in make_client_key_exchange\n");
            exit(-1);
            break;
    }
    
    serialize_client_key_exchange(client_key_exchange, &(client_key_exchange_h->message), (&client_key_exchange_h->length));
    
    free_client_key_exchange(client_key_exchange);
    
    return client_key_exchange_h;
}

void make_RSA_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param){
    
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
    unsigned char *pre_master_key_enc = malloc(sizeof(unsigned char)*256);
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

void make_DHE_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param){
    
    // Set server key exchange type
    dhe_server_key_exchange_t *server_key_exchange = (dhe_server_key_exchange_t*)TLS_param->server_key_ex;
    
    // Verify signature
    if(verify_DHE_server_key_ex_sign(TLS_param->server_certificate, TLS_param->client_random, TLS_param->server_random, server_key_exchange,TLS_param->cipher_suite.au) == 0){
        printf("\nError in make_DHE_client_key_exchange, signature not valid\n");
        exit(-1);
    }
    printf("Signature is valid");
    
    // Initialize and set Diffie-Hellman parameters
    DH *dh_key = DH_new();
    dh_key->g = server_key_exchange->g;
    dh_key->p = server_key_exchange->p;
    if(DH_generate_key(dh_key) != 1)
        printf("Error in DH_generate_key\n");
    
    // Initialize pre master key
    unsigned char *pre_master_key = malloc(DH_size(dh_key));
    int pre_master_key_len = 0;
    pre_master_key_len = DH_compute_key(pre_master_key, server_key_exchange->pubKey, dh_key);
    
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
    client_key_ex->key_length = BN_num_bytes(dh_key->pub_key);
    client_key_ex->key = malloc(sizeof(unsigned char)*client_key_ex->key_length);
    BN_bn2bin(dh_key->pub_key, client_key_ex->key);
    
    // Clean up
    DH_free(dh_key);
    free(pre_master_key);
}

void make_ECDHE_client_key_exchange(client_key_exchange_t *client_key_ex, TLS_parameters_t *TLS_param){
    
    // Set server key exchange algorithm
    ecdhe_server_key_exchange_t *server_key_exchange = (ecdhe_server_key_exchange_t * )TLS_param->server_key_ex;
    
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

handshake_t * make_finished_message(TLS_parameters_t *TLS_param ) {
    
    // Initialize finished
    handshake_t *finished_h = malloc(sizeof(handshake_t));
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
