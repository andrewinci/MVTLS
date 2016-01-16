//
//  SSL/TLS Project
//  SSLServer.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "TLS.h"

/*
 * Choice a cipher suite, make server_hello
 * client_hello : client hello message received from client
 */
handshake * make_server_hello(TLS_parameters *TLS_param, handshake_hello *client_hello){
	// Make ServerHello (without SessionID)
	session_id *session= malloc(sizeof(session_id));
	session->session_lenght = 0x00;
	session->session_id = NULL;
	handshake_hello *server_hello = make_hello(*session);
	server_hello->TLS_version = TLS1_2;
	
	// Choose a cipher suite
	free(server_hello->cipher_suites.cipher_id);
	server_hello->cipher_suites.length = 0x02;
	server_hello->cipher_suites.cipher_id = malloc(2);
	int choosen_suite = rand()%8; //specify the number of supported cipher suite
	*(server_hello->cipher_suites.cipher_id) = client_hello->cipher_suites.cipher_id[choosen_suite];
	TLS_param->cipher_suite = *(server_hello->cipher_suites.cipher_id);

	// Copy server's random
	memcpy(TLS_param->server_random,&(server_hello->random.UNIX_time), 4);
	memcpy(TLS_param->server_random+4, server_hello->random.random_bytes, 28);

	// Make ServerHello
	handshake *server_hello_h = malloc(sizeof(handshake));
	server_hello_h->type = SERVER_HELLO;
	server_hello_h->message = NULL;
	server_hello_h->length = 0;
	serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);
	
	free_hello(server_hello);
	free(session);
	
	return server_hello_h;
}

handshake * make_certificate(TLS_parameters *TLS_param){
	// Make and send Certificate
	certificate_message *cert_message = make_certificate_message("../certificates/server.pem");
	
	handshake *certificate_h = malloc(sizeof(handshake));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));
	
	free_certificate_message(cert_message);
	
	return certificate_h;
}

handshake * make_server_key_exchange(TLS_parameters *TLS_param){
	
	//DH serverkey exchange
	//generate ephemeral diffie helman parameters
	DH *privkey;
	int codes;
	
	/* Generate the parameters to be used */
	if(NULL == (privkey = DH_new())){
		printf("error in DH new\n");
	}
	if(1 != DH_generate_parameters_ex(privkey, 100, DH_GENERATOR_2 , NULL)){
		printf("error in parameter generate\n");
	}
	
	if(1 != DH_check(privkey, &codes)){
		printf("error in DH check\n");
	}
	if(codes != 0)
	{
		/* Problems have been found with the generated parameters */
		/* Handle these here - we'll just abort for this example */
		printf("DH_check failed\n");
		abort();
	}
	
	/* Generate the public and private key pair */
	if(1 != DH_generate_key(privkey)){
		printf("Error in DH_generate_key\n");
	}

    //make server_key_ex packet
    
	DH_server_key_exchange *server_key_ex = malloc(sizeof(DH_server_key_exchange));
	server_key_ex->g = BN_new();
	server_key_ex->p = BN_new();
	server_key_ex->pubKey = BN_new();
	//copy DH params in the message struct
	if(BN_copy(server_key_ex->g, privkey->g)==NULL)
		printf("\nError in copy DH parameters\n");
	if(BN_copy(server_key_ex->p, privkey->p)==NULL)
		printf("\nError in copy DH parameters\n");
	if(BN_copy(server_key_ex->pubKey, privkey->pub_key)==NULL)
		printf("\nError in copy DH parameters\n");

    server_key_ex->sign_hash_alg = 0x0106; //already rot
    
    //add signature
    sign_DH_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex);
	
	//serialize and make handshake
	handshake *server_key_ex_h = malloc(sizeof(handshake));
	
	server_key_ex_h->type = SERVER_KEY_EXCHANGE;
	serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, DHE_RSA_KX);
    
    //save parameters for second step
    TLS_param->server_key_ex = server_key_ex;
    //save private DH key
    TLS_param->private_key = BN_new();
    BN_copy(TLS_param->private_key, privkey->priv_key);

	return server_key_ex_h;
}

handshake * make_server_hello_done() {
	// Make ServerDone
	handshake *server_hello_done = malloc(sizeof(handshake));
	server_hello_done->type = SERVER_DONE;
	server_hello_done->length =0x00;
	server_hello_done->message = NULL;
	return server_hello_done;
}
