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
    server_hello->cipher_suites = malloc(sizeof(cipher_suite_t));
    srand(time(NULL));
	int choosen_suite = rand()%(client_hello->cipher_suite_len/2); //specify the number of supported cipher suite
    
    memcpy(server_hello->cipher_suites, &(client_hello->cipher_suites[choosen_suite]), sizeof(cipher_suite_t));
    
    // Set cipher suite in global param
    TLS_param->cipher_suite = client_hello->cipher_suites[choosen_suite];

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
    certificate_message *cert_message = NULL;
    
    if(TLS_param->cipher_suite.au == RSA_AU)
        cert_message = make_certificate_message("../certificates/serverRSA.pem");
    else if(TLS_param->cipher_suite.au == DSS_AU)
        cert_message = make_certificate_message("../certificates/serverDSA.pem");
    
	TLS_param->server_certificate = cert_message->X509_certificate;
    TLS_param->server_certificate->references+=1;
	handshake *certificate_h = malloc(sizeof(handshake));
	certificate_h->type = CERTIFICATE;
	serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));
	
	free_certificate_message(cert_message);
	
	return certificate_h;
}

handshake * make_server_key_exchange(TLS_parameters *TLS_param){
    
    uint16_t kx = TLS_param->cipher_suite.kx;
    if(kx == DHE_KX){
        
        //DH servervkey exchange
        //generate ephemeral diffie helman parameters
        DH *privkey;
        int codes;
        
        /* Generate the parameters to be used */
        if(NULL == (privkey = DH_new())){
            printf("error in DH new\n");
        }
        if(1 != DH_generate_parameters_ex(privkey, 1024, DH_GENERATOR_2 , NULL)){
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
        
        DHE_server_key_exchange *server_key_ex = malloc(sizeof(DHE_server_key_exchange));
        server_key_ex->g = BN_dup(privkey->g);
        server_key_ex->p = BN_dup(privkey->p);
        server_key_ex->pubKey = BN_dup(privkey->pub_key);
        //copy DH params in the message struct
     
        
        server_key_ex->sign_hash_alg = 0x0106; //already rotated
        
        //add signature
        sign_DHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);
        
        //serialize and make handshake
        handshake *server_key_ex_h = malloc(sizeof(handshake));
        
        server_key_ex_h->type = SERVER_KEY_EXCHANGE;
        serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, DHE_KX);
        
        //save parameters for second step
        TLS_param->server_key_ex = server_key_ex;
        //save private DH key
        TLS_param->private_key = BN_new();
        BN_copy(TLS_param->private_key, privkey->priv_key);

        DH_free(privkey);
        
        return server_key_ex_h;
        
    }
    else if( kx == ECDHE_KX){
        
        EC_KEY *key;

        uint16_t curve_name = NID_secp256k1;
        /* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
        if(NULL == (key = EC_KEY_new_by_curve_name( curve_name))){
            printf("\nError setting  EC parameters\n");
        }
        
        /* Generate the private and public key */
        if(1 != EC_KEY_generate_key(key)){
            printf("\nError in generate EC keys\n");
        }
        
        //save server private key
        TLS_param->private_key = BN_dup(EC_KEY_get0_private_key(key));
        
        // Make server key ex pachet
        ECDHE_server_key_exchange *server_key_ex = malloc(sizeof(ECDHE_server_key_exchange));
        server_key_ex->named_curve = curve_name;
        
        // get public key
        server_key_ex->pub_key = BN_new();
        EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, server_key_ex->pub_key, NULL);
        
        server_key_ex->sign_hash_alg = 0x0106; //already rotated
        
        //add signature
        sign_ECDHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex);
        
        
        //serialize and make handshake
        handshake *server_key_ex_h = malloc(sizeof(handshake));
        
        server_key_ex_h->type = SERVER_KEY_EXCHANGE;
        serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, ECDHE_KX);
        
        //save parameters for second step
        TLS_param->server_key_ex = server_key_ex;

        EC_KEY_free(key);
        return server_key_ex_h;
    }
    return NULL;
}

handshake * make_server_hello_done() {
	// Make ServerDone
	handshake *server_hello_done = malloc(sizeof(handshake));
	server_hello_done->type = SERVER_DONE;
	server_hello_done->length =0x00;
	server_hello_done->message = NULL;
	return server_hello_done;
}
