/**
 *	SSL/TLS Project
 *	\file ServerClientHandshakeProtocol.h
 *
 *	This file is used to manage the handshake protocol
 *
 *	\date Created on 27/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#include "ServerClientHandshakeProtocol.h"

/**
 * Serialize a handshake into a byte stream
 *
 *	\param h: the handshake to serialize
 *	\param stream: a pointer to NULL, it will filled with the serialized handshake
 *	\param streamLen: the length of the serialized message
 */
void serialize_handshake(handshake_t *h, unsigned char **stream, uint32_t *streamLen){
	unsigned char *buff = malloc(sizeof(unsigned char)*(h->length+4));
	*stream = buff;
	*buff = h->type;
	buff++;

	uint32_t len = REV32(h->length)>>8;
	memcpy(buff, &len, 3);
	buff+=3;

	memcpy(buff, h->message, h->length);

	*streamLen = h->length+4;
}

/**
 * Send an handshake through a channel
 *
 *	\param ch: the channel to use
 *	\param h: the handshake to send
 *	\return 1 if the send is succeeded, 0 otherwise
 */
int send_handshake(channel_t *ch, handshake_t *h){
    record_t *to_send;
    uint32_t serialized_handshake_len;
    unsigned char *serialized_handshake;
    serialize_handshake(h, &serialized_handshake, &serialized_handshake_len);
    
    to_send = make_record(serialized_handshake, serialized_handshake_len, HANDSHAKE, TLS1_2);
    
    int result = send_record(ch, to_send);
    
    free(serialized_handshake);
    free_record(to_send);
    
    return result;
}

/**
 * De-serialize a stream of byte into an handshake. 
 *
 *	\param message: the serialized handshake 
 *	\param messageLen: the message length
 *	\return return the de-serialized handshake message
 */
handshake_t *deserialize_handshake(unsigned char *message, uint32_t messageLen){
	handshake_t *h = malloc(sizeof(handshake_t));
	h->type = *message;
	message++;

	uint32_t len;
	memcpy(&len, message, 3);
	len = REV32(len)>>8;
	h->length = len;
	message+=3;

	h->message = malloc(sizeof(unsigned char)*(h->length));
	memcpy(h->message,message,h->length);

	return h;
}

/**
 * Print the handshake struct
 *
 *	\param h: handshake to print
 *	\param verbosity: how many details to print (0 none, 1 the binary, 2 details, 3 record)
 *	\param kx: the key exchange algorithm, useful in key_exchange messages
 */
void print_handshake(handshake_t *h, int verbosity, key_exchange_algorithm kx){

	if(verbosity == 2 || verbosity == 3){
		if (h->type == CLIENT_HELLO){
			server_client_hello_t *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
			print_hello(client_hello);
			free_hello(client_hello);
		}
		else if (h->type == SERVER_HELLO){
			server_client_hello_t *server_hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);
			print_hello(server_hello);
			free_hello(server_hello);
		}
		else if (h->type == CERTIFICATE){
			certificate_message_t *certificate = deserialize_certificate_message(h->message, h->length);
			PEM_write_X509(stdout, certificate->X509_certificate);
			free_certificate_message(certificate);
		}
		else if (h->type == SERVER_KEY_EXCHANGE){
			server_key_exchange_t *server_key_exchange = deserialize_server_key_exchange(h->message, h->length, kx);
			print_server_key_exchange(server_key_exchange, kx);
			free_server_key_exchange(server_key_exchange, kx);
		}
		else if (h->type == CLIENT_KEY_EXCHANGE){
			client_key_exchange_t *client_key_exchange = deserialize_client_key_exchange(h->message, h->length);
			print_client_key_exchange(client_key_exchange);
			free_client_key_exchange(client_key_exchange);
		}
        printf("\n");
	}
    if(verbosity == 1 || verbosity == 2){
        unsigned char *message = NULL;
        uint32_t messageLen = 0;
        serialize_handshake(h, &message, &messageLen);
        if(message != NULL){
            for(int i=0; i<messageLen; i++){
                if(i%9 == 0)
                    printf("\n");
                printf("%02x ", *(message+i));
            }
            printf("\n");
            free(message);
        }
    }
	else if (verbosity == 3){
		record_t *r = malloc(sizeof(record_t));
		r->type = HANDSHAKE;
		r->version = TLS1_2;
		uint32_t len = 0;
		serialize_handshake(h, &r->message, &len);
		r->length = (uint16_t)len;
		print_record(r);
	}
}

/**
 * Dealloc memory of handshake struct
 * 
 *	\param h: the handshake to be freed
 */
void free_handshake(handshake_t *h){
	if(h==NULL)
		return;
	free(h->message);
	free(h);
}
