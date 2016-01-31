//
//  client.c
//  SSLXcodeProject
//
//  Created by Darka on 12/01/16.
//  Copyright © 2016 Darka. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "TLS.h"
#define USAGE 	"TLSClient: TLS1.2 version handshake\n"\
				"\n"\
				"Usage:  \n"\
				"  TLSClient [args] \n"\
				" \n"\
				"Options: \n"\
				"  Specify cipher suite id (not hex) \n"\
				"    -c  --cipher_id        [id]\n"\
				"   \n"\
				"  Cipher suite name     \n"\
				"    -n  --name             [name]\n"\
				"   \n"\
				"  Specify key exchange    \n"\
				"    -x  --key_exchange    (RSA|DHE|ECDHE)  \n"\
				"   \n"\
				"  Specify authentication algorithm \n"\
				"    -a  --auth_algorithm  (RSA|DSS|ECDSA) \n"\
				" \n"\
				"  Specify verbosity \n"\
				"    -v     0 default (1|2) \n"\
				" \n"\
				"  Specify hash algorithm \n"\
				"    -h  --hash_algorithm  (MD5|SHA1|SHA224|SHA256|SHA384|SHA512) \n"\
				" \n"\
				"  Show supported cipher suites \n"\
				"    -l --list\n"\
				" \n"\
				"  Show this help \n"\
				"    --help \n\n"

void onPacketReceive(channel_t *ch, packet_basic_t *p);
void do_handshake(int to_send_cipher_suite_len, cipher_suite_t to_send_cipher_suite[]);

int v=0;

TLS_parameters_t TLS_param;

int main(int argc, char **argv) {
    
    //PARAMETERS
    int to_send_cipher_suite_len = 0;
    cipher_suite_t to_send_cipher_suite[NUM_CIPHER_SUITE];
    key_exchange_algorithm kx = DHE_KX;
    authentication_algorithm au = NONE_AU;
    hash_algorithm ha = NONE_H;
    for(int i=1;i<argc;i+=2){
        if(strcmp(argv[i], "-c")==0 || strcmp(argv[i], "--cipher_id")==0){
            cipher_suite_t c = get_cipher_suite_by_id(atoi(argv[i+1]));
            if(c.name!=NULL){
                to_send_cipher_suite[to_send_cipher_suite_len] = c;
                //printf("Load:%s\n",to_send_cipher_suite[to_send_cipher_suite_len].name);
                to_send_cipher_suite_len++;
            }else
                printf("cannot parse %s %s or the requested cipher suite is not supported yet.\n",argv[i],argv[i+1]);
        }
        
        else if(strcmp(argv[i], "-n")==0 || strcmp(argv[i], "--name")==0){
            cipher_suite_t c = get_cipher_suite_by_name(argv[i+1]);
            if(c.name!=NULL){
                to_send_cipher_suite[to_send_cipher_suite_len] = c;
                //printf("Load:%s\n",to_send_cipher_suite[to_send_cipher_suite_len].name);
                to_send_cipher_suite_len++;
            }else
                printf("cannot parse %s %s or the requested cipher suite is not supported yet.\n",argv[i],argv[i+1]);
        }

        else if(strcmp(argv[i], "-x")==0 || strcmp(argv[i], "--key_exchange")==0){
            if(strcmp("RSA", argv[i+1])==0)
                kx = RSA_KX;
            else if(strcmp("DHE", argv[i+1])==0)
                kx = DHE_KX;
            else if(strcmp("ECDHE", argv[i+1])==0)
                kx = ECDHE_KX;
        }
        else if(strcmp(argv[i], "-a")==0 || strcmp(argv[i], "--auth_algorithm")==0){
            if(strcmp("RSA", argv[i+1])==0)
                au = RSA_AU;
            else if(strcmp("DSS", argv[i+1])==0)
                au = DSS_AU;
            else if(strcmp("ECDSA", argv[i+1])==0)
                au = ECDSA_AU;
        }
        else if(strcmp(argv[i], "-h")==0 || strcmp(argv[i], "--hash_algorithm")==0){
            if(strcmp("MD5", argv[i+1])==0)
                ha = MD5_H;
            else if(strcmp("SHA1", argv[i+1])==0)
                ha = SHA1_H;
            else if(strcmp("SHA224", argv[i+1])==0)
                ha = SHA224_H;
            else if(strcmp("SHA256", argv[i+1])==0)
                ha = SHA256_H;
            else if(strcmp("SHA384", argv[i+1])==0)
                ha = SHA384_H;
            else if(strcmp("SHA512", argv[i+1])==0)
                ha = SHA512_H;
        }
        else if(strcmp(argv[i], "-v")==0 ){
            v = atoi(argv[i+1]);
        }
        else if(argc == 2 && strcmp(argv[i], "--help")==0){
            printf("%s",USAGE);
            return 0;
        }
        else if( argc == 2 && (strcmp(argv[i], "-l")==0 || strcmp(argv[i], "--list")==0)){
            int num_added = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
            printf("Supported cipher suite are the follows:\n");
            for(int i=0;i<num_added;i++)
                printf("%s\n",to_send_cipher_suite[i].name);
            return 0;
        }
    }
    // if no option load all cipher suite
    if(to_send_cipher_suite_len == 0 && kx == NONE_KX && au == NONE_AU && ha == NONE_H){
        to_send_cipher_suite_len = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
        
        printf("All supported cipher suite are loaded\n");
        printf("use --help for show the help\n");
    }else if (to_send_cipher_suite_len == 0){
        int num_added = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
        //for(int j=0;j<num_added;j++)
            //printf("Load %s\n",to_send_cipher_suite[j+to_send_cipher_suite_len].name);
        to_send_cipher_suite_len+=num_added;
        if(to_send_cipher_suite_len == 0){
            printf("no supported cipher suite with the selected arguments\n");
            printf("%s",USAGE);
            return 0;
        }
            
    }
    TLS_param.handshake_messages = NULL;
	
    do_handshake(to_send_cipher_suite_len, to_send_cipher_suite);
}

/*
 * Send packets for starting a secure connection (handshake)
 */
void do_handshake(int to_send_cipher_suite_len, cipher_suite_t to_send_cipher_suite[]) {
    // Setup the channel
    char *fileName = "TLSchannel.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    channel_t *client2server = create_channel(fileName, channelFrom, channelTo);
    set_on_receive(client2server, &onPacketReceive);
    
    TLS_param.previous_state = 0x0000;
    printf("*** TLS client is started ***\n\n");
    
    // Make ClientHello
    printf(">>> Client hello\n");
    handshake_t *client_hello = make_client_hello(TLS_param.client_random, to_send_cipher_suite, to_send_cipher_suite_len);
    print_handshake(client_hello,v,TLS_param.cipher_suite.kx);

    send_handshake(client2server, client_hello);
    backup_handshake(&TLS_param,client_hello);
    free_handshake(client_hello);
    
    // Start channel and listener for new messages
    start_listener(client2server);
    wait_channel(client2server);
    
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
    
    free(client2server);
    
    free(TLS_param.handshake_messages);
    free(TLS_param.master_secret);
    X509_free(TLS_param.server_certificate);
    
    //free_server_key_exchange(TLS_param.server_key_ex, TLS_param.cipher_suite.kx); //ToDo : somewhere we free part of this struct hence this call give an error
    //free openssl resources
    CRYPTO_cleanup_all_ex_data();
}

/*
 * Function called from basic protocol
 * when a message is received
 */
void onPacketReceive(channel_t *client2server, packet_basic_t *p){

	// Get record and print
	record_t *r = deserialize_record(p->message, p->length);
	if(r->type == CHANGE_CIPHER_SPEC){
		printf("\n<<< Change cipher spec\n");
		if(v>1)
			print_record(r);

		free_record(r);
		free_packet(p);
	}
	else if(r->type == HANDSHAKE){
		handshake_t *h = deserialize_handshake(r->message, r->length);

		free_record(r);
		free_packet(p);

		switch (h->type) {

			case SERVER_HELLO:
				if(TLS_param.previous_state == 0x0000){
					TLS_param.previous_state = SERVER_HELLO;
					backup_handshake(&TLS_param,h);
					server_client_hello_t *server_hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);

					printf("\n<<< Server Hello\n");
					print_handshake(h, v, TLS_param.cipher_suite.kx);

					// Extract data for next steps
					TLS_param.cipher_suite = *server_hello->cipher_suites;
					TLS_param.tls_version = server_hello->TLS_version;

					// Backup server random
					memcpy(TLS_param.server_random,&(server_hello->random.UNIX_time), 4);
					memcpy(TLS_param.server_random+4, server_hello->random.random_bytes, 28);

					free_hello(server_hello);
				}
				break;

			case CERTIFICATE:

				if(TLS_param.previous_state == SERVER_HELLO){

					TLS_param.previous_state = CERTIFICATE;

					backup_handshake(&TLS_param, h);
					printf("\n<<< Certificate\n");
					print_handshake(h, v, TLS_param.cipher_suite.kx);

					certificate_message_t *certificate_m = deserialize_certificate_message(h->message, h->length);
					TLS_param.server_certificate = certificate_m->X509_certificate;
					TLS_param.server_certificate->references+=1;

					free_certificate_message(certificate_m);
				}
				break;

			case SERVER_KEY_EXCHANGE:

				if(TLS_param.previous_state == CERTIFICATE){
					TLS_param.previous_state = SERVER_KEY_EXCHANGE;
					printf("\n<<< Server Key Exchange\n");
					print_handshake(h, v, TLS_param.cipher_suite.kx);
					//save the server key exchange parameters
					TLS_param.server_key_ex = deserialize_server_key_exchange(h->message, h->length, TLS_param.cipher_suite.kx);
					backup_handshake(&TLS_param, h);
				}
				break;

			case SERVER_DONE:

				if((TLS_param.previous_state == CERTIFICATE || TLS_param.previous_state == SERVER_KEY_EXCHANGE)){
					backup_handshake(&TLS_param,h);
					printf("\n<<< Server Hello Done\n");
					print_handshake(h, v, TLS_param.cipher_suite.kx);

					// Make client_key_eschange packet
					handshake_t * client_key_exchange = make_client_key_exchange(&TLS_param, TLS_param.cipher_suite.kx);
					backup_handshake(&TLS_param, client_key_exchange);
					send_handshake(client2server, client_key_exchange);
					printf("\n>>> Client Key Exchange\n");
					print_handshake(client_key_exchange, v, TLS_param.cipher_suite.kx);
					free_handshake(client_key_exchange);

					printf("\n>>> Change cipher spec\n");
					record_t* change_cipher_spec = make_change_cipher_spec();
					send_record(client2server, change_cipher_spec);
					if(v>1)
						print_record(change_cipher_spec);
					free_record(change_cipher_spec);

					printf("\n>>> Finished\n");
					handshake_t *finished = make_finished_message(&TLS_param);
					send_handshake(client2server, finished);
					print_handshake(finished, v, TLS_param.cipher_suite.kx);
					free_handshake(finished);
				}
				break;

			case FINISHED:

				printf("\n<<< Finished\n");
				print_handshake(h, v, TLS_param.cipher_suite.kx);
				free_handshake(h);
				stop_channel(client2server);
				break;

			default:
				break;
		}
		free_handshake(h);
	}
}
