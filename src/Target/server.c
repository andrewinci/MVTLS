//
//  server.c
//  SSLXcodeProject
//
//  Created by Darka on 12/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include <stdio.h>
#include "TLS.h"

void print_random();
void print_master_secret();
void compute_set_master_key_RSA(client_key_exchange_t *client_key_exchange);
void compute_set_master_key_DHE(client_key_exchange_t *cliet_public);
void compute_set_master_key_ECDHE(client_key_exchange_t *cliet_public);
void onPacketReceive(channel_t *server2client, packet_basic_t *p);
void do_handshake();

int v = 0;
TLS_parameters_t TLS_param;

int main(int argc, char **argv) {
    if(argc>1 && strcmp(argv[1], "-v")==0 ){
        v = atoi(argv[2]);
    }
    do_handshake();
}

void do_handshake() {
    // Setup the channel
    char *fileName = "TLSchannel.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";
    channel_t *server2client = create_channel(fileName, channelFrom, channelTo);
    set_on_receive(server2client, &onPacketReceive);
    
    TLS_param.previous_state = 0x00;
    
    // Start channel and listener for new messages
    start_listener(server2client);
    printf("*** TLS server is started ***\n");
    
    wait_channel(server2client);
    
    // Print details about connection
    printf("\nServer random:\n");
    for(int i=0;i<32;i++)
        printf("%02x ",TLS_param.server_random[i]);
    printf("\nClient random:\n");
    for(int i=0;i<32;i++)
        printf("%02x ",TLS_param.client_random[i]);
    printf("\n");
    
    printf("\nCertificate details:\n");
    printf("%s",TLS_param.server_certificate->name);
    
    printf("\nCipher suite: %s",TLS_param.cipher_suite.name);
    
    printf("\nMaster key: \n");
    for(int i=0;i<TLS_param.master_secret_len;i++)
        printf("%02X ",TLS_param.master_secret[i]);
    printf("\n");
    
    // Clean up
    free(TLS_param.master_secret);
    free(TLS_param.handshake_messages);
    free(server2client);
    BN_free(TLS_param.private_key);//
    X509_free(TLS_param.server_certificate);
    //free_server_key_exchange(TLS_param.server_key_ex, TLS_param.cipher_suite.kx); //ToDo : somewhere we free part of this struct hence this call give an error
    CRYPTO_cleanup_all_ex_data();
}

/*
 * Function called from basic protocol
 * when a message is received
 */
void onPacketReceive(channel_t *server2client, packet_basic_t *p){

	// Get record and print
	record_t *r = deserialize_record(p->message, p->length);
	if(r->type == CHANGE_CIPHER_SPEC){
		printf("\n<<< Change CipherSpec\n");
		print_record(r);

		free_record(r);
		free_packet(p);
	}
	else if(r->type == HANDSHAKE){
		handshake_t *h = deserialize_handshake(r->message, r->length);

		free_record(r);
		free_packet(p);

		switch (h->type) {
			case CLIENT_HELLO:
				if(TLS_param.previous_state == 0x00){
					TLS_param.previous_state = CLIENT_HELLO;
					backup_handshake(&TLS_param, h);
					server_client_hello_t *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);

					printf("<<< Client Hello\n");
					print_handshake(h,v,TLS_param.cipher_suite.kx);

					// Backup client random
					memcpy(TLS_param.client_random,&(client_hello->random.UNIX_time),4);
					memcpy(TLS_param.client_random+4,client_hello->random.random_bytes,28);

					// Choose a cipher suite and send ServerHello
					printf("\n>>> Server Hello\n");
					handshake_t * server_hello = make_server_hello(&TLS_param, client_hello);
					print_handshake(server_hello,v,TLS_param.cipher_suite.kx);
					send_handshake(server2client, server_hello);

					// Backup ServerHello
					backup_handshake(&TLS_param, server_hello);

					free_handshake(server_hello);
					free_hello(client_hello);

					// Retrieve and send Certificate
					printf("\n>>> Certificate\n");
					handshake_t *certificate = make_certificate(&TLS_param);
					print_handshake(certificate,v,TLS_param.cipher_suite.kx);
					send_handshake(server2client, certificate);
					backup_handshake(&TLS_param, certificate);
					free_handshake(certificate);

					// Make server key exchange if needed
					if(TLS_param.cipher_suite.kx == DHE_KX || TLS_param.cipher_suite.kx == ECDHE_KX){
						handshake_t *server_key_exchange = make_server_key_exchange(&TLS_param);
						printf("\n>>> Server key exchange\n");
						print_handshake(server_key_exchange,v,TLS_param.cipher_suite.kx);
						send_handshake(server2client, server_key_exchange);
						backup_handshake(&TLS_param, server_key_exchange);

						free_handshake(server_key_exchange);
					}

					// Make and send ServerHelloDone
					printf("\n>>> Server hello done\n");
					handshake_t * server_hello_done = make_server_hello_done();
					print_handshake(server_hello_done,v,TLS_param.cipher_suite.kx);
					send_handshake(server2client, server_hello_done);
					backup_handshake(&TLS_param, server_hello_done);
					free_handshake(server_hello_done);

				}
				break;

			case CLIENT_KEY_EXCHANGE:
				if (TLS_param.previous_state == CLIENT_HELLO){
					TLS_param.previous_state = CLIENT_KEY_EXCHANGE;
					backup_handshake(&TLS_param, h);
					printf("\n<<< Client Key Exchange\n");
                    print_handshake(h,v,TLS_param.cipher_suite.kx);
                    client_key_exchange_t *client_key_exchange = deserialize_client_key_exchange(h->message, h->length);
                    switch (TLS_param.cipher_suite.kx) {
                        case RSA_KX:
                            compute_set_master_key_RSA(client_key_exchange);
                            break;
                        case DHE_KX:
                            compute_set_master_key_DHE(client_key_exchange);
                            break;
                        case ECDHE_KX:
                            compute_set_master_key_ECDHE(client_key_exchange);
                            break;
                        default:
                            break;
                    }
                    free_client_key_exchange(client_key_exchange);
				}
				break;

			case FINISHED:
				if (TLS_param.previous_state == CLIENT_KEY_EXCHANGE){
					// Receive Finished
					backup_handshake(&TLS_param, h);
					printf("\n<<< Finished\n");
					print_handshake(h,v,TLS_param.cipher_suite.kx);
					free_handshake(h);

					// Send ChangeCipherSpec
					printf("\n>>> Change CipherSpec\n");
					record_t* change_cipher_spec = make_change_cipher_spec();
					send_record(server2client, change_cipher_spec);
					print_record(change_cipher_spec);
					free_record(change_cipher_spec);

					// Send Finished
					printf("\n>>> Finished\n");

					handshake_t *finished = make_finished_message(&TLS_param);
					send_handshake(server2client, finished);
					print_handshake(finished,v,TLS_param.cipher_suite.kx);
					free_handshake(finished);

					stop_channel(server2client);
				}
				break;

			default:
				break;
		}

		free_handshake(h);
	}
}


void compute_set_master_key_RSA(client_key_exchange_t *client_key_exchange) {
    //get private key from file
    RSA *privateKey = NULL;
    FILE *fp;
    
    if(NULL != (fp= fopen("../certificates/serverRSA.key", "r")) )
    {
	  privateKey=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
	  if(privateKey==NULL)
	  {
		printf("\nerror in retrieve private key");
		exit(-1);
	  }
    }
    fclose(fp);
    
    unsigned char *pre_master_key = malloc(RSA_size(privateKey));
    if(!RSA_private_decrypt(client_key_exchange->key_length, client_key_exchange->key, pre_master_key, privateKey, RSA_PKCS1_PADDING))
    {
	  printf("Error decrypt\n");
	  exit(-1);
    }
    
    //make master key
    unsigned char seed[64];
    memcpy(seed, TLS_param.client_random, 32);
    memcpy(seed+32, TLS_param.server_random, 32);
    
    const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
    TLS_param.master_secret_len = 48;
    PRF(hash_function, pre_master_key, 48, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);
    RSA_free(privateKey);
    
    free(pre_master_key);
}

void compute_set_master_key_DHE(client_key_exchange_t *cliet_public){
    DH *privkey = DH_new();
    dhe_server_key_exchange_t *server_key_exchange = TLS_param.server_key_ex;
    
    privkey->g = BN_dup(server_key_exchange->g);
    privkey->p = BN_dup(server_key_exchange->p);
    privkey->priv_key = TLS_param.private_key;
    privkey->pub_key = NULL;
    privkey->pub_key = BN_bin2bn(cliet_public->key, cliet_public->key_length, NULL);
    
    //make pre master key
    unsigned char *pre_master_key = malloc(DH_size(privkey));
    int pre_master_key_len = 0;
    pre_master_key_len = DH_compute_key(pre_master_key, privkey->pub_key, privkey);
    
    //compute master key
    unsigned char seed[64];
    memcpy(seed, TLS_param.client_random, 32);
    memcpy(seed+32, TLS_param.server_random, 32);
    
    const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
    TLS_param.master_secret_len = 48;
    PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);
    
    free_server_key_exchange(TLS_param.server_key_ex, TLS_param.cipher_suite.kx);
    DH_free(privkey);
    free(pre_master_key);
}

void compute_set_master_key_ECDHE(client_key_exchange_t *cliet_public){
    ecdhe_server_key_exchange_t *server_key_exchange = (ecdhe_server_key_exchange_t *) TLS_param.server_key_ex;
    EC_KEY *key = EC_KEY_new_by_curve_name(server_key_exchange->named_curve);
    
    //get and set public key
    BIGNUM *pub_key = BN_bin2bn(cliet_public->key, cliet_public->key_length, NULL);
    EC_POINT *pub_key_point = EC_POINT_bn2point(EC_KEY_get0_group(key), pub_key, NULL, NULL);
    EC_KEY_set_public_key(key, pub_key_point);
    EC_POINT_free(pub_key_point);
    BN_free(pub_key);
    
    //set private key
    EC_KEY_set_private_key(key, TLS_param.private_key);

    // compute master secret
    int field_size, pre_master_len;
    unsigned char *pre_master;
    
    /* Calculate the size of the buffer for the shared secret */
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    pre_master_len = (field_size+7)/8;
    
    /* Allocate the memory for the shared secret */
    pre_master = malloc(sizeof(unsigned char)*pre_master_len);
    
    /* Derive the shared secret */
    TLS_param.master_secret_len = ECDH_compute_key(pre_master, pre_master_len, EC_KEY_get0_public_key(key), key, NULL);
    
    // Derive master key
    unsigned char seed[64];
    memcpy(seed, TLS_param.client_random, 32);
    memcpy(seed+32, TLS_param.server_random, 32);
    const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
    TLS_param.master_secret_len = 48;
    
    //compute and set pre master key
    PRF(hash_function, pre_master, pre_master_len, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);
    
    EC_KEY_free(key);
    free(pre_master);
}
