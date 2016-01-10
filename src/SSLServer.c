//
//  SSL/TLS Project
//  SSLServer.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include <stdio.h>

#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"
#include <openssl/err.h>

void onPacketReceive(channel *server, packet_basic *p);
void backup_handshake(handshake *h);

void RSA_server_key_exchange(handshake *h);
void client_hello_received(handshake *h);
void send_change_cipher_spec();
void finished_message_receive(handshake *h);

channel *server2client = NULL;

uint16_t previous_state = 0x00; //TODO
uint16_t cipher_suite =0x00;
unsigned char client_random[32];
unsigned char server_random[32];
unsigned char *master_secret = NULL;
int master_secret_len = 0;

int handshake_messages_len = 0;
unsigned char *handshake_messages = NULL;

int main() {
    //setting up the channel
    char *fileName = "SSLchannel.txt";
    char *channelFrom = "Server";
    char *channelTo = "Client";
    server2client = create_channel(fileName, channelFrom, channelTo, SERVER);
    
    set_on_receive(server2client, &onPacketReceive);
    //star channel and listener to new message
    start_channel(server2client);
    
    printf("*** TLS server is start ***\n");
    wait_channel(server2client);
	free(server2client);
}

/*
 * Function is automatically called from
 * basic protocol when a message is received
 */
void onPacketReceive(channel *server, packet_basic *p){
    
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
        free_record(r);
		free_packet(p);
        
        if(h->type == CLIENT_HELLO && previous_state == 0x00){
            previous_state = CLIENT_HELLO;
            client_hello_received(h);
        }
        else if (h->type == CLIENT_KEY_EXCHANGE && previous_state == CLIENT_HELLO){
            previous_state = CHANGE_CIPHER_SPEC;
            //make and send server key exchange
            if(get_kx_algorithm(cipher_suite)==RSA_KX){
                RSA_server_key_exchange(h);
            }
        }
        else if (h->type == FINISHED){
			//send change cipher spec
			send_change_cipher_spec();
			
			//send finished message
            finished_message_receive(h);
			
			//free globals and close channel
			free(master_secret);
			free(handshake_messages);
			stop_channel(server);
        }
    }
    else if(r->type == CHANGE_CIPHER_SPEC){
		printf("\n<<< Change cipher spec\n");
        free_record(r);
        free_packet(p);
    }
}

/*
 * Choice a cipher suite, make server_hello and send it
 * client_hello : client hello message received from client
 * ch : comunication channel
 */
void send_server_hello(handshake_hello *client_hello) {
    //Make server hello without session
    session_id *session= malloc(sizeof(session_id));
    session->session_lenght =0x00;
    session->session_id = NULL;
    
    handshake_hello *server_hello = make_hello(*session);
	//free cipher suite automatically generated from make hello
	free(server_hello->cipher_suites.cipher_id);
	
    server_hello->TLS_version = TLS1_2;
    //choose a cipher suite
    server_hello->cipher_suites.length = 0x02;
   
	server_hello->cipher_suites.cipher_id = malloc(2);
    //TODO : choice a cipher suite randomly
    int choosen_suite = rand()%4;//((client_hello->cipher_suites.length)/2); //the length correspond to the byte len
    *(server_hello->cipher_suites.cipher_id) = client_hello->cipher_suites.cipher_id[choosen_suite];

    cipher_suite = *(server_hello->cipher_suites.cipher_id);
    printf("\nCipher suite :%04x\n",cipher_suite);
    
    //copy server random
    memcpy(server_random,&(server_hello->random.UNIX_time), 4);
    memcpy(server_random+4, server_hello->random.random_bytes, 28);
    
    //make Server hello handshake
    handshake *server_hello_h = malloc(sizeof(handshake));
    server_hello_h->type = SERVER_HELLO;
    server_hello_h->message = NULL;
    server_hello_h->length = 0;
    serialize_client_server_hello(server_hello, &(server_hello_h->message), &(server_hello_h->length), SERVER_MODE);

    //send server hello
    printf("\n>>> Server Hello\n");
    print_handshake(server_hello_h);

    send_handshake(server2client, server_hello_h);
    backup_handshake(server_hello_h);

    free_handshake(server_hello_h);
    free_hello(server_hello);
	free(session);
}

void client_hello_received(handshake *h) {
    backup_handshake(h);
    handshake_hello *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
    
    printf("<<< Client Hello\n");
    print_handshake(h);
    
    //copy client random
    memcpy(client_random,&(client_hello->random.UNIX_time),4);
    memcpy(client_random+4,client_hello->random.random_bytes,28);
    
    send_server_hello(client_hello);
    //clear received packet
    free_hello(client_hello);
    
    //Print random for server and client
    printf("\nServer random :\n");
    for(int i=0;i<32;i++)
        printf("%02x ",server_random[i]);
    printf("\nClient random :\n");
    for(int i=0;i<32;i++)
        printf("%02x ",client_random[i]);
    printf("\n");
    
    //make and send certificate packet
    char cert_names[] = "../certificates/serverRSA.pem";
    char **cert_list= malloc(1*sizeof(char *));
    cert_list[0] = cert_names;
    
    certificate_message *cert_message = make_certificate_message("../certificates/serverRSA.pem");
    free(cert_list);
    
    handshake *certificate_h = malloc(sizeof(handshake));
    certificate_h->type = CERTIFICATE;
    serialize_certificate_message(cert_message, &(certificate_h->message), &(certificate_h->length));
    free_certificate_message(cert_message);
    
    printf("\n>>> Certificate\n");
    print_handshake(certificate_h);
    
    send_handshake(server2client, certificate_h);
    backup_handshake(certificate_h);
    free_handshake(certificate_h);
    
    /*
     if the key exchange method is one of these:
     DHE_DSS DHE_RSA DH_anon
     send: Server Key Exchange Message
     */
    /*for these key method exchange :
     RSA DH_DSS DH_RSA
     don't send Server Key Exchange
     but server hello done
     */
    key_exchange_algorithm kx = get_kx_algorithm(cipher_suite);
    if(kx==RSA_KX || kx==DH_DSS_KX || kx == DH_RSA_KX){
        //make Server Hello Done
        handshake *server_hello_done = malloc(sizeof(handshake));
        server_hello_done->type = SERVER_DONE;
        server_hello_done->length =0x00;
        server_hello_done->message = NULL;
        printf("\n>>> Server hello done\n");
        print_handshake(server_hello_done);
        send_handshake(server2client, server_hello_done);
        backup_handshake(server_hello_done);
        
        free_handshake(server_hello_done);
    }
    else{
        //TODO : implement server key exchange message
    }
    //backup and free
    free_handshake(h);
}

void RSA_server_key_exchange(handshake *h) {
    backup_handshake(h);
    printf("\n<<< Client Key Exchange\n");
    print_handshake(h);
    
    //extract private key from file
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
    
    //extract pre master key encrypted from message
    unsigned char *pre_master_key_enc = NULL;
    uint32_t key_en_len = 0;
    deserialize_key_exchange(h->length, h->message, &pre_master_key_enc, &key_en_len, RSA_KX);
    
    unsigned char pre_master_key[48] ={0};
    if(!RSA_private_decrypt(key_en_len, pre_master_key_enc, pre_master_key, privateKey, RSA_PKCS1_PADDING)) //TODO : check
    {
        printf("Error decrypt\n");
        exit(-1);
    }

    //make master key
    unsigned char seed[64] ;
    memcpy(seed, client_random, 32);
    memcpy(seed+32, server_random, 32);
    
    master_secret_len = 48;
    const EVP_MD *hash_function = get_hash_function(cipher_suite);
    PRF(hash_function, pre_master_key, PRE_MASTER_KEY_LEN, "master secret", seed, 64, master_secret_len, &master_secret);
    
    printf("\nMaster secret:\n");
    for(int i=0;i<master_secret_len;i++)
        printf("%02x ",master_secret[i]);
    printf("\n");
    free(pre_master_key_enc);
    RSA_free(privateKey);
    
    //free
    free_handshake(h);
}

void send_change_cipher_spec() {
    //make and send change cipher spec message
    printf("\n>>> Change cipher spec\n");
    record *change_cipher_spec_message = malloc(sizeof(record));
    change_cipher_spec_message->type = CHANGE_CIPHER_SPEC;
    change_cipher_spec_message->version = TLS1_2;
    change_cipher_spec_message->lenght = 0x01;
    change_cipher_spec_message->message = malloc(1);
    *(change_cipher_spec_message->message) = 0x01;
    send_record(server2client, change_cipher_spec_message);
    
    //print sended message
    unsigned char *message;
    uint16_t len;
    serialize_record(change_cipher_spec_message, &message, &len);
    for (int i=0; i<len; i++) {
        if(i%9==0)
            printf("\n");
        printf("%02x ",message[i]);
    }
    free(message);
    free_record(change_cipher_spec_message);
}

void finished_message_receive(handshake *h){
    backup_handshake(h);
    printf("\n<<< Finished\n");
    print_handshake(h);
    
//  print handshakes
//	printf("\nHandshake messages:\n");
//	for(int i=0;i<handshake_messages_len;i++)
//	printf("%02x ",handshake_messages[i]);
//	printf("\n");
    
    //make and send finished message
    handshake *finished_h = malloc(sizeof(handshake));
    finished_h->type = FINISHED;
    const EVP_MD *hash_function = get_hash_function(cipher_suite);
    //compute hash of handshake messages
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, hash_function, NULL);
    EVP_DigestUpdate(mdctx, handshake_messages, handshake_messages_len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    
    unsigned char *finished_message = NULL;
    int finished_message_len = 12;
    PRF(hash_function, master_secret, master_secret_len, "client finished", md_value, md_len, finished_message_len, &finished_message);
    finished_h->length = finished_message_len;
    finished_h->message = finished_message;
    printf("\n>>> Finished\n");
    
    send_handshake(server2client, finished_h);

    print_handshake(finished_h);
    
    free_handshake(finished_h);
    free_handshake(h);
}

/*
 * This function appends to handshake_messages the handshake h
 */
void backup_handshake(handshake *h){
    
    unsigned char *handshake_message = NULL;
    uint32_t handshake_message_len = 0;
    
    serialize_handshake(h, &handshake_message, &handshake_message_len);
    handshake_messages = realloc(handshake_messages, handshake_messages_len+handshake_message_len);
    memcpy(handshake_messages+handshake_messages_len, handshake_message, handshake_message_len);
    handshake_messages_len += handshake_message_len;
    free(handshake_message);
}