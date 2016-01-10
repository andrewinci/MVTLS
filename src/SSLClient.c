//
//  SSL/TLS Project
//  SSLClient.c
//
//  Created on 30/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
#include <stdio.h>
#include "ServerClientHandshakeProtocol.h"
#include "ServerClientRecordProtocol.h"
#include <openssl/rand.h>


void onPacketReceive(channel *ch, packet_basic *p);
void backup_handshake(handshake *h);

//Handshake message functions
void send_client_hello();
void server_hello_received(handshake *h);
void certificate_received(handshake *h);
void RSA_client_key_exchange();
void server_hello_done_received(handshake *h);
void send_change_cipher_spec();
void send_finished_message();

channel *client2server = NULL;

//variable for comunication and protocol
uint16_t cipher_suite =0x0000;
certificate_message *server_certificate;
uint16_t tls_version = 0x0000;
uint16_t previous_state = 0x0000;
unsigned char client_random[32] = {0};
unsigned char server_random[32] = {0};

//master secret
int master_secret_len = 0;
unsigned char *master_secret = NULL;

//all exchanged message are appended here
int handshake_messages_len = 0;
unsigned char *handshake_messages = NULL;


int main() {
    //setting up the channel
    char *fileName = "SSLchannel.txt";
    char *channelFrom = "Client";
    char *channelTo = "Server";
    client2server = create_channel(fileName, channelFrom, channelTo, CLIENT);
    set_on_receive(client2server, &onPacketReceive);
    
    //star channel and listener for new message
	printf("*** TLS client is start ***\n\n");
    start_channel(client2server);
	//TODO: brutto problema
    send_client_hello();

    wait_channel(client2server);
    
    free(client2server);
}

/*
 * Function is automatically called from
 * basic protocol when a message is received
 */
void onPacketReceive(channel *ch, packet_basic *p){
    //get record and print
    record *r = deserialize_record(p->message, p->messageLen);
    if(r->type == HANDSHAKE){
        handshake *h = deserialize_handshake(r->message, r->lenght);
		free_record(r);
		free_packet(p);
        if(h->type == SERVER_HELLO && previous_state==0x0000){
            server_hello_received(h);
        }
        else if(h->type == CERTIFICATE && previous_state == SERVER_HELLO){
            certificate_received(h);
        }
        else if(h->type == SERVER_DONE && previous_state == CERTIFICATE){
            server_hello_done_received(h);
            send_change_cipher_spec();
            send_finished_message();
        }
        else if( h->type == FINISHED){
            printf("\n<<< Finished\n");
            print_handshake(h);
            //free and close
            free(handshake_messages);
            free(master_secret);
            stop_channel(client2server);
            
        }
    }
}

void send_client_hello() {
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
    
    //print send and backup
    printf(">>> Client hello\n");
    print_handshake(client_hello_h);
    send_handshake(client2server, client_hello_h);
    backup_handshake(client_hello_h);
    
    //save the generated random
    memcpy(client_random,&(client_hello->random.UNIX_time),4);
    memcpy(client_random+4,client_hello->random.random_bytes,28);
    
    free(session);
    free_hello(client_hello);
    free_handshake(client_hello_h);
}

/*
 * Extract data from server_hello 
 * h : handshake with server_hello message
 */
void server_hello_received(handshake *h) {
    backup_handshake(h);
    
    handshake_hello *hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);
    printf("\n<<< Server Hello\n");
    print_handshake(h);
    
    //extract data for next steps
    cipher_suite = *(hello->cipher_suites.cipher_id);
    
    printf("\nCipher suite :%04x\n",cipher_suite);
    
    tls_version = hello->TLS_version;

    //save server random
    memcpy(server_random,&(hello->random.UNIX_time), 4);
    memcpy(server_random+4, hello->random.random_bytes, 28);
    
    //print server and client random
    printf("Server random :\n");
    for(int i=0;i<32;i++)
        printf("%02x ",server_random[i]);
    printf("\nClient random :\n");
    for(int i=0;i<32;i++)
        printf("%02x ",client_random[i]);
    
    free_handshake(h);
    free_hello(hello);
    previous_state = SERVER_HELLO;
}

/*
 * Extract data from certificate message
 * h : handshake with certificate
 */
void certificate_received(handshake *h) {
    backup_handshake(h);
    printf("\n<<< Certificate\n");
    print_handshake(h);
    certificate_message *certificate_m = deserialize_certificate_message(h->message, h->length);
    server_certificate = certificate_m;
    printf("\nCertificate dettails: %s\n",certificate_m->X509_certificate->name);
    previous_state = CERTIFICATE;
	free_handshake(h);
}

/*
 * Manage RSA key exchange
 */
void RSA_client_key_exchange() {
    
    //get RSA struct
    EVP_PKEY *pubkey = NULL;
    RSA *rsa = NULL;
    
    pubkey = X509_get_pubkey(server_certificate->X509_certificate);
    rsa = EVP_PKEY_get1_RSA(pubkey);

    EVP_PKEY_free(pubkey);
    //generate pre   secret key
    unsigned char *pre_master_key = calloc(PRE_MASTER_KEY_LEN,1);
    //the first 2 byte coincide with the tls version
    uint16_t temp = REV16(tls_version);
    memcpy(pre_master_key,&temp , 2);
    
    //the rest are random
    RAND_pseudo_bytes(pre_master_key+2, 46);
    unsigned char pre_master_key_enc[256];
    
    //encrypt pre_master_key
    uint32_t key_len = RSA_public_encrypt(PRE_MASTER_KEY_LEN, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);

    //serialize and send
    unsigned char *message = NULL;
    uint32_t len = 0;
    serialize_key_exchange(key_len, pre_master_key_enc, &message, &len, RSA_KX);
    
    //make handshake packet
    handshake *client_key_exchange = malloc(sizeof(handshake));
    client_key_exchange->type = CLIENT_KEY_EXCHANGE;
    client_key_exchange->message = message;
    client_key_exchange->length = len;

    printf("\n>>> Client Key Exchange\n");
    print_handshake(client_key_exchange);
    
    send_handshake(client2server, client_key_exchange);
    backup_handshake(client_key_exchange);
    
    free_handshake(client_key_exchange);
    
    //make master key
    unsigned char seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed+32, server_random, 32);
    
    const EVP_MD *hash_function = get_hash_function(cipher_suite);
    master_secret_len = 48;
    PRF(hash_function, pre_master_key, PRE_MASTER_KEY_LEN, "master secret", seed, 64, master_secret_len, &master_secret);

    printf("\nMaster secret:\n");
    for(int i=0;i<48;i++)
        printf("%02x ",master_secret[i]);
    printf("\n");
    
    free_certificate_message(server_certificate);
    RSA_free(rsa);
    free(pre_master_key);
}

void server_hello_done_received(handshake *h) {
    backup_handshake(h);
    printf("<<< Server Hello Done\n");
    print_handshake(h);
    
    //make Client Key Exchange Message
    key_exchange_algorithm kx = get_kx_algorithm(cipher_suite);
    if(kx == RSA_KX){
        RSA_client_key_exchange();
        
    }
    else{
        printf("\nExchange method not implemented yet\n");
        exit(-1);
    }
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
    send_record(client2server, change_cipher_spec_message);
    unsigned char *message;
    uint16_t len;
    serialize_record(change_cipher_spec_message, &message, &len);
    for (int i=0; i<len; i++) {
        if(i%9==0)
            printf("\n");
        printf("%02x ",message[i]);
    }
	printf("\n");
    free(message);
    free_record(change_cipher_spec_message);
}

//make and send finished message
void send_finished_message() {
	//print handshakes
//	printf("\nHandshake messages :\n");
//	for(int i=0;i<handshake_messages_len;i++)
//	printf("%02x ",handshake_messages[i]);
//	printf("\n");
	
	//make finished handshake
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
    
    send_handshake(client2server, finished_h);
    
    print_handshake(finished_h);
    free_handshake(finished_h);
}

/******************************/
void backup_handshake(handshake *h){
    
    unsigned char *temp_message = NULL;
    uint32_t temp_message_len = 0;
    
    serialize_handshake(h, &temp_message, &temp_message_len);
    if(handshake_messages == NULL)
        handshake_messages = malloc(handshake_messages_len+temp_message_len);
    else
        handshake_messages = realloc(handshake_messages, handshake_messages_len+temp_message_len);
    
    memcpy(handshake_messages+handshake_messages_len, temp_message, temp_message_len);
    handshake_messages_len += temp_message_len;
    free(temp_message);
}