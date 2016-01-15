//
//  server.c
//  SSLXcodeProject
//
//  Created by Darka on 12/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include <stdio.h>
#include "TLS.h"

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
	printf("*** TLS server is started ***\n");

	// Start channel and listener for new messages
	start_listener(server2client);
	wait_channel(server2client);

	free(server2client);
}

void print_random(void) {
	// Print randoms of server and client
	printf("\nServer random:\n");
	for(int i=0;i<32;i++)
		printf("%02x ",TLS_param.server_random[i]);
	printf("\nClient random:\n");
	for(int i=0;i<32;i++)
		printf("%02x ",TLS_param.client_random[i]);
	printf("\n");
}

void print_master_secret(void) {
	// Print MasterSecret
	printf("\nMaster secret:\n");
	for(int i=0;i<TLS_param.master_secret_len;i++)
		printf("%02x ",TLS_param.master_secret[i]);
	printf("\n");
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
					
					printf("\nCipher suite: %04x\n",TLS_param.cipher_suite);
					print_random();

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
					key_exchange_algorithm kx = get_kx_algorithm(TLS_param.cipher_suite);
					if(kx==RSA_KX || kx==DH_DSS_KX || kx == DH_RSA_KX){
						//RSA DH_DSS DH_RSA
						printf("\n>>> Server hello done\n");
						handshake * server_hello_done = make_server_hello_done();
						print_handshake(server_hello_done);
						send_handshake(server2client, server_hello_done);
						backup_handshake(&TLS_param, server_hello_done);
						free_handshake(server_hello_done);
					}
					else if(kx == DHE_RSA_KX){
						//DHE_DSS DHE_RSA DH_anon
						handshake * server_key_exchange = make_server_key_exchange(&TLS_param);
						printf("\n>>> Server key exchange\n");
						print_handshake(server_key_exchange);
						send_handshake(server2client, server_key_exchange);
						backup_handshake(&TLS_param, server_key_exchange);
					
						free_handshake(server_key_exchange);

						make_server_hello_done(server2client, &TLS_param);
					}
				}
			break;
				
			case CLIENT_KEY_EXCHANGE:
				if (TLS_param.previous_state == CLIENT_HELLO){
					TLS_param.previous_state = CLIENT_KEY_EXCHANGE;

					// ToDo FIX THIS TOO
					printf("\n<<< Client Key Exchange\n");
					key_exchange_algorithm kx = get_kx_algorithm(TLS_param.cipher_suite);
					if(kx == RSA_KX)
						manage_RSA_client_key_exchange(&TLS_param, h);
					else if(kx == DHE_RSA_KX || kx == DHE_DSS_KX)
						manage_DHE_server_key_exchange(h);
					print_master_secret();
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
					
					// Free global variables and close the channel
					free(TLS_param.master_secret);
					free(TLS_param.handshake_messages);
					stop_channel(server2client);
				}
				break;
				
			default:
				break;
		}
		free_handshake(h);	
	}
}