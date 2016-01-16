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
	
	unsigned char *temp_message = NULL;
	uint32_t temp_message_len = 0;
	
	serialize_handshake(h, &temp_message, &temp_message_len);
	if(TLS_param->handshake_messages == NULL)
		TLS_param->handshake_messages = malloc(TLS_param->handshake_messages_len+temp_message_len);
	else
		TLS_param->handshake_messages = realloc(TLS_param->handshake_messages, TLS_param->handshake_messages_len+temp_message_len);
	
	memcpy(TLS_param->handshake_messages+TLS_param->handshake_messages_len, temp_message, temp_message_len);
	TLS_param->handshake_messages_len += temp_message_len;
	free(temp_message);
}

/* Functions for send message */

handshake * make_client_hello(unsigned char *client_random){
	//make client hello without session
	session_id *session= malloc(sizeof(session_id));
	session->session_lenght =0x00;
	session->session_id = NULL;
	handshake_hello *client_hello = make_hello(*session);
	client_hello->TLS_version = TLS1_2;
	
	//make handshake
	handshake *client_hello_h = malloc(sizeof(handshake));
	client_hello_h->type = CLIENT_HELLO;
	
	//put message in the handshake packet
	serialize_client_server_hello(client_hello, &(client_hello_h->message), &(client_hello_h->length), CLIENT_MODE);

	//save the generated random
	memcpy(client_random,&(client_hello->random.UNIX_time),4);
	memcpy(client_random+4,client_hello->random.random_bytes,28);
	
	free(session);
	free_hello(client_hello);
	return client_hello_h;
}

handshake * make_client_key_exchange(TLS_parameters *TLS_param, uint16_t key_ex_alg){
    if(key_ex_alg == RSA_KX){

        //make pre master key
        int pre_master_key_len = 58;
        unsigned char *pre_master_key = calloc(pre_master_key_len,1);

        uint16_t temp = REV16(TLS_param->tls_version);
        memcpy(pre_master_key,&temp , 2);

        RAND_pseudo_bytes(pre_master_key+2, 46);
        
        //make master key
        unsigned char seed[64];
        memcpy(seed, TLS_param->client_random, 32);
        memcpy(seed+32, TLS_param->server_random, 32);
        
        const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite);
        TLS_param->master_secret_len = 48;
        
        //compute and set pre master key
        PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);
        
        //encrypt with certificate RSA key
        EVP_PKEY *pubkey = NULL;
        RSA *rsa = NULL;
        
        pubkey = X509_get_pubkey(TLS_param->server_certificate);
        rsa = EVP_PKEY_get1_RSA(pubkey);
        
        EVP_PKEY_free(pubkey);
        
        //encrypt pre_master_key
        unsigned char *pre_master_key_enc = malloc(256);
        int pre_master_key_enc_len = 0;
        pre_master_key_enc_len = RSA_public_encrypt(pre_master_key_len, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);
        RSA_free(rsa);
        
        client_key_exchange *rsa_server_key_ex = malloc(sizeof(client_key_exchange));
        rsa_server_key_ex->key = pre_master_key_enc;
        rsa_server_key_ex->key_length = pre_master_key_enc_len;
        unsigned char *message = NULL;
        uint32_t len = 0;
        serialize_client_key_exchange(rsa_server_key_ex, &message, &len);
        
        free(rsa_server_key_ex->key);
        free(rsa_server_key_ex);
        
        handshake *client_key_exchange = malloc(sizeof(handshake));
        client_key_exchange->type = CLIENT_KEY_EXCHANGE;
        client_key_exchange->message = message;
        client_key_exchange->length = len;

        return client_key_exchange;
    }
    else if (key_ex_alg == DHE_RSA_KX){
        DH_server_key_exchange *server_key_exchange = TLS_param->server_key_ex;
        // ToDo verify sign
        DH *privkey = DH_new();
        privkey->g = server_key_exchange->g;
        privkey->p = server_key_exchange->p;
        if(1 != DH_generate_key(privkey)){
            printf("Error in DH_generate_key\n");
        }
        
        //make pre master key
        unsigned char *pre_master_key = malloc(DH_size(privkey));
        int pre_master_key_len = 0;
        pre_master_key_len = DH_compute_key(pre_master_key, server_key_exchange->pubKey, privkey);
        
        //make master key
        unsigned char seed[64];
        memcpy(seed, TLS_param->client_random, 32);
        memcpy(seed+32, TLS_param->server_random, 32);
        
        const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite);
        TLS_param->master_secret_len = 48;
        
        //compute and set pre master key
        PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);
        
        //make client key ex packet
        client_key_exchange *client_key_exchange = malloc(sizeof(client_key_exchange));
        client_key_exchange->key_length = BN_num_bytes(privkey->pub_key);
        client_key_exchange->key = malloc(client_key_exchange->key_length);
        BN_bn2bin(privkey->pub_key, client_key_exchange->key);

        //make handshake
        handshake *client_key_exchange_h = malloc(sizeof(client_key_exchange));
        client_key_exchange_h->type = CLIENT_KEY_EXCHANGE;
        
        serialize_client_key_exchange(client_key_exchange, &client_key_exchange_h->message, &client_key_exchange_h->length);
        
        free(client_key_exchange);
        return client_key_exchange_h;
    }
    return NULL;
}

record * make_change_cipher_spec() {

	//make and send change cipher spec message
	record *change_cipher_spec_message = malloc(sizeof(record));
	change_cipher_spec_message->type = CHANGE_CIPHER_SPEC;
	change_cipher_spec_message->version = TLS1_2;
	change_cipher_spec_message->lenght = 0x01;
	change_cipher_spec_message->message = malloc(1);
	*(change_cipher_spec_message->message) = 0x01;
	return change_cipher_spec_message;
}

handshake * make_finished_message(TLS_parameters *TLS_param ) {
	
	//make finished handshake
	handshake *finished_h = malloc(sizeof(handshake));
	finished_h->type = FINISHED;
	const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite);
	
	//compute hash of handshake messages
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, hash_function, NULL);
	EVP_DigestUpdate(mdctx, TLS_param->handshake_messages, TLS_param->handshake_messages_len);
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	
	unsigned char *finished_message = NULL;
	int finished_message_len = 12;
	PRF(hash_function, TLS_param->master_secret, TLS_param->master_secret_len, "client finished", md_value, md_len, finished_message_len, &finished_message);
	finished_h->length = finished_message_len;
	finished_h->message = finished_message;
	return finished_h;
}