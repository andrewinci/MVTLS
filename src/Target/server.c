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
void compute_set_master_key_RSA(client_key_exchange *client_key_exchange);
void compute_set_master_key_DH(client_key_exchange *cliet_public);
void onPacketReceive(channel *server2client, packet_basic *p);

TLS_parameters TLS_param;

int main() {
	// Setup the channel
	char *fileName = "SSLchannel.txt";
	char *channelFrom = "Server";
	char *channelTo = "Client";
	channel *server2client = create_channel(fileName, channelFrom, channelTo, SERVER);
	set_on_receive(server2client, &onPacketReceive);
	
	TLS_param.previous_state = 0x00;
    //ToDo: load certificate
	printf("*** TLS server is started ***\n");

	// Start channel and listener for new messages
	start_listener(server2client);
	wait_channel(server2client);
    
    //print details about the connection
    print_random();
    printf("\nCertificate details: %s\n", TLS_param.server_certificate->name);
    printf("\nCipher suite: %s",TLS_param.cipher_suite.name);
    printf("\nMaster key: \n");
    for(int i=0;i<TLS_param.master_secret_len;i++)
        printf("%02X ",TLS_param.master_secret[i]);

    free(TLS_param.master_secret);
	free(TLS_param.handshake_messages);
	free(server2client);
	X509_free(TLS_param.server_certificate);
	//free openssl resources
	CRYPTO_cleanup_all_ex_data();
}

/*
 * Function called from basic protocol
 * when a message is received
 */
void onPacketReceive(channel *server2client, packet_basic *p){
	
	// Get record and print
	record *r = deserialize_record(p->message, p->messageLen);
	if(r->type == CHANGE_CIPHER_SPEC){
		printf("\n<<< Change CipherSpec\n");
		print_record(r);
		
		free_record(r);
		free_packet(p);
	}
	else if(r->type == HANDSHAKE){
		handshake *h = deserialize_handshake(r->message, r->lenght);
		
		free_record(r);
		free_packet(p);
		
		switch (h->type) {
				
			case CLIENT_HELLO:
				if(TLS_param.previous_state == 0x00){
					TLS_param.previous_state = CLIENT_HELLO;
					backup_handshake(&TLS_param, h);
					handshake_hello *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
					
					printf("<<< Client Hello\n");
					print_handshake(h);
						
					// Backup client random
					memcpy(TLS_param.client_random,&(client_hello->random.UNIX_time),4);
					memcpy(TLS_param.client_random+4,client_hello->random.random_bytes,28);
						
					// Choose a cipher suite and send ServerHello
					printf("\n>>> Server Hello\n");
					handshake * server_hello = make_server_hello(&TLS_param, client_hello);
					print_handshake(server_hello);
					send_handshake(server2client, server_hello);
					
					// Backup ServerHello
					backup_handshake(&TLS_param, server_hello);

					free_handshake(server_hello);
					free_hello(client_hello);
						
					// Retrieve and send Certificate
					printf("\n>>> Certificate\n");
					handshake *certificate = make_certificate(&TLS_param);
					print_handshake(certificate);
					send_handshake(server2client, certificate);
					backup_handshake(&TLS_param, certificate);
					free_handshake(certificate);

					// ToDo FIX THIS MESS

                    if(TLS_param.cipher_suite.kx == DHE_KX){

						//DHE_DSS DHE_RSA DH_anon
						handshake * server_key_exchange = make_server_key_exchange(&TLS_param);
						printf("\n>>> Server key exchange\n");
						print_handshake(server_key_exchange);
						send_handshake(server2client, server_key_exchange);
						backup_handshake(&TLS_param, server_key_exchange);
					
						free_handshake(server_key_exchange);
					}

					// Make and send ServerHelloDone
					printf("\n>>> Server hello done\n");
					handshake * server_hello_done = make_server_hello_done();
					print_handshake(server_hello_done);
					send_handshake(server2client, server_hello_done);
					backup_handshake(&TLS_param, server_hello_done);
					free_handshake(server_hello_done);
                    
				}
			break;
				
			case CLIENT_KEY_EXCHANGE:
				if (TLS_param.previous_state == CLIENT_HELLO){
					TLS_param.previous_state = CLIENT_KEY_EXCHANGE;
                    
                    backup_handshake(&TLS_param, h);
					// ToDo FIX THIS TOO
					printf("\n<<< Client Key Exchange\n");
                    if(TLS_param.cipher_suite.kx == RSA_KX){
                        print_handshake(h);
                        client_key_exchange *client_key_exchange = deserialize_client_key_exchange(h->length, h->message);
                        compute_set_master_key_RSA(client_key_exchange);
                    }
                    else if(TLS_param.cipher_suite.kx == DHE_KX){
                        client_key_exchange *cliet_public = deserialize_client_key_exchange(h->length, h->message);
                        compute_set_master_key_DH(cliet_public);
                    }

				}
				break;
			
			case FINISHED:
				if (TLS_param.previous_state == CLIENT_KEY_EXCHANGE){
					// Receive Finished
					backup_handshake(&TLS_param, h);
					printf("\n<<< Finished\n");
					print_handshake(h);
					free_handshake(h);
					
					// Send ChangeCipherSpec
					printf("\n>>> Change CipherSpec\n");
					record* change_cipher_spec = make_change_cipher_spec();
					send_record(server2client, change_cipher_spec);
					print_record(change_cipher_spec);
					free_record(change_cipher_spec);
					
					// Send Finished
					printf("\n>>> Finished\n");
					
					handshake *finished = make_finished_message(&TLS_param);
					send_handshake(server2client, finished);
					print_handshake(finished);
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

void print_random() {
    // Print randoms of server and client
    printf("\nServer random:\n");
    for(int i=0;i<32;i++)
        printf("%02x ",TLS_param.server_random[i]);
    printf("\nClient random:\n");
    for(int i=0;i<32;i++)
        printf("%02x ",TLS_param.client_random[i]);
    printf("\n");
}

void print_master_secret() {
    // Print MasterSecret
    printf("\nMaster secret:\n");
    for(int i=0;i<TLS_param.master_secret_len;i++)
        printf("%02x ",TLS_param.master_secret[i]);
    printf("\n");
    }

void compute_set_master_key_RSA(client_key_exchange *client_key_exchange) {
    //get private key from file
    RSA *privateKey = NULL;
    FILE *fp;
    
    if(NULL != (fp= fopen("../certificates/server.key", "r")) )
    {
        privateKey=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        if(privateKey==NULL)
        {
            printf("\nerror in retrieve private key");
            exit(-1);
        }
    }
    fclose(fp);
    unsigned char *pre_master_key=malloc(100);
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
    free(client_key_exchange->key);
    free(client_key_exchange);
}

void compute_set_master_key_DH(client_key_exchange *cliet_public){
    DH *privkey = DH_new();
    DH_server_key_exchange *server_key_exchange = TLS_param.server_key_ex;
    privkey->g = server_key_exchange->g;
    privkey->p = server_key_exchange->p;
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
    
    free_DH_server_key_exchange(TLS_param.server_key_ex);
}
