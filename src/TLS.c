/**
 *	SSL/TLS Project
 *	\file TLS.c
 *	This file provide a set of function for the TLS protocol.
 *
 *	\date Created on 13/01/16.
 *	\copyright Copyright © 2016 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#include "TLS.h"

/** Verbosity of the output */
int verbosity = 0;

/** Connection parameters */
handshake_parameters_t TLS_param;

/**
 * Compute the master key for RSA using the previous server key exchange stored in TLS_param
 * and the client key exchange. The master key, master key length is stored also in
 * TLS_param.
 *
 *	\param client_key_exchange: the client key exchange sent by client
 */
void compute_set_master_key_RSA(client_key_exchange_t *client_key_exchange) {
	// Get private key from file
	RSA *privateKey = NULL;
	FILE *fp;

	if((fp= fopen("../certificates/serverRSA.key", "r")) != NULL){
		privateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
		if(privateKey == NULL){
			printf("\nError in retrieve private key");
			exit(-1);
		}
	}
	fclose(fp);

	// Decrypt pre-master key
	unsigned char *pre_master_key = malloc(RSA_size(privateKey));
	if(!RSA_private_decrypt(client_key_exchange->key_length, client_key_exchange->key, pre_master_key, privateKey, RSA_PKCS1_PADDING)){
		printf("\nError in RSA_private_decrypt\n");
		exit(-1);
	}

	// Make master key
	unsigned char seed[64];
	memcpy(seed, TLS_param.client_random, 32);
	memcpy(seed+32, TLS_param.server_random, 32);
	const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
	TLS_param.master_secret_len = 48;
	PRF(hash_function, pre_master_key, 48, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);
	RSA_free(privateKey);

	// Clean up
	free(pre_master_key);
}

/**
 * Compute the master key for DHE using the previous server key exchange stored in TLS_param
 * and the client key exchange. The master key, master key length is stored also in
 * TLS_param.
 *
 *	\param client_key_exchange: the client key exchange sent by client
 */
void compute_set_master_key_DHE(client_key_exchange_t *client_key_exchange){
	DH *privkey = DH_new();
	dhe_server_key_exchange_t *server_key_exchange = TLS_param.server_key_ex;

	// Copy parameters
	privkey->g = BN_dup(server_key_exchange->g);
	privkey->p = BN_dup(server_key_exchange->p);
	privkey->priv_key = BN_dup(TLS_param.private_key);
	privkey->pub_key = NULL;
	privkey->pub_key = BN_bin2bn(client_key_exchange->key, client_key_exchange->key_length, NULL);

	// Make pre master key
	unsigned char *pre_master_key = malloc(DH_size(privkey));
	int pre_master_key_len = 0;
	pre_master_key_len = DH_compute_key(pre_master_key, privkey->pub_key, privkey);

	// Compute master secret
	unsigned char seed[64];
	memcpy(seed, TLS_param.client_random, 32);
	memcpy(seed+32, TLS_param.server_random, 32);
	const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
	TLS_param.master_secret_len = 48;
	PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);

	// Clean up
	BN_clear_free(TLS_param.private_key);
	DH_free(privkey);
	free(pre_master_key);
}

/**
 * Compute the master key for ECDHE using the previous server key exchange stored in TLS_param
 * and the client key exchange. The master key, master key length is stored also in 
 * TLS_param.
 *
 *	\param client_key_exchange: the client key exchange sent by client
 */
void compute_set_master_key_ECDHE(client_key_exchange_t *client_key_exchange){
	ecdhe_server_key_exchange_t *server_key_exchange = (ecdhe_server_key_exchange_t *) TLS_param.server_key_ex;
	EC_KEY *key = EC_KEY_new_by_curve_name(server_key_exchange->named_curve);

	// Get public key
	BIGNUM *pub_key = BN_bin2bn(client_key_exchange->key, client_key_exchange->key_length, NULL);
	EC_POINT *pub_key_point = EC_POINT_bn2point(EC_KEY_get0_group(key), pub_key, NULL, NULL);
	EC_KEY_set_public_key(key, pub_key_point);
	EC_POINT_free(pub_key_point);
	BN_free(pub_key);

	// Set private key
	EC_KEY_set_private_key(key, TLS_param.private_key);

	int field_size, pre_master_len;
	unsigned char *pre_master;

	// Calculate the size of the buffer for the shared secret
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	pre_master_len = (field_size+7)/8;

	// Allocate the memory for the shared secret
	pre_master = malloc(sizeof(unsigned char)*pre_master_len);

	// Derive the shared secret
	TLS_param.master_secret_len = ECDH_compute_key(pre_master, pre_master_len, EC_KEY_get0_public_key(key), key, NULL);

	// Compute master secret
	unsigned char seed[64];
	memcpy(seed, TLS_param.client_random, 32);
	memcpy(seed+32, TLS_param.server_random, 32);
	const EVP_MD *hash_function = get_hash_function(TLS_param.cipher_suite.hash);
	TLS_param.master_secret_len = 48;
	PRF(hash_function, pre_master, pre_master_len, "master secret", seed, 64, TLS_param.master_secret_len, &TLS_param.master_secret);

	// Clean up
	BN_clear_free(TLS_param.private_key);
	EC_KEY_free(key);
	free(pre_master);
}

/**
 * Function called from transport protocol
 * when a message is received by the client.
 *
 *	\param channel: the communication channel
 *	\param p: the received packet
 */
void onClientPacketReceive(channel_t *channel, packet_transport_t *p){

	// Get record and print
	record_t *r = deserialize_record(p->message, p->length);
	if(r->type == CHANGE_CIPHER_SPEC){
		TLS_param.previous_state = CHANGE_CIPHER_SPEC;
		if(verbosity>0){
			printf("\n<<< Change cipher spec\n");
			print_record(r);
		}

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
					server_client_hello_t *server_hello = deserialize_client_server_hello(h->message, h->length, SERVER_MODE);

					if(verbosity!=0)
						printf("\n<<< Server Hello\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);

					// Extract data for next steps
					TLS_param.cipher_suite = *server_hello->cipher_suites;
					TLS_param.tls_version = server_hello->TLS_version;

					// Save server random
					memcpy(TLS_param.server_random,&(server_hello->random.UNIX_time), 4);
					memcpy(TLS_param.server_random+4, server_hello->random.random_bytes, 28);

					free_hello(server_hello);
				}
				break;

			case CERTIFICATE:
				if(TLS_param.previous_state == SERVER_HELLO){
					TLS_param.previous_state = CERTIFICATE;
					backup_handshake(&TLS_param, h);

					if(verbosity>0)
						printf("\n<<< Certificate\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);

					certificate_message_t *certificate_m = deserialize_certificate_message(h->message, h->length);
					TLS_param.server_certificate = certificate_m->X509_certificate;
					TLS_param.server_certificate->references+=1;

					free_certificate_message(certificate_m);
				}
				break;

			case SERVER_KEY_EXCHANGE:
				if(TLS_param.previous_state == CERTIFICATE){
					TLS_param.previous_state = SERVER_KEY_EXCHANGE;

					if(verbosity>0)
						printf("\n<<< Server Key Exchange\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);

					// Save server key exchange parameters
					TLS_param.server_key_ex = deserialize_server_key_exchange(h->message, h->length, TLS_param.cipher_suite.kx);
					backup_handshake(&TLS_param, h);
				}
				break;

			case SERVER_DONE:
				if((TLS_param.previous_state == CERTIFICATE || TLS_param.previous_state == SERVER_KEY_EXCHANGE)){
					backup_handshake(&TLS_param,h);

					if(verbosity>0)
						printf("\n<<< Server Hello Done\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);

					// Make client key exchange
					handshake_t * client_key_exchange = make_client_key_exchange(&TLS_param, TLS_param.cipher_suite.kx);
					backup_handshake(&TLS_param, client_key_exchange);
					send_handshake(channel, client_key_exchange);
					if(verbosity>0)
						printf("\n>>> Client Key Exchange\n");
					print_handshake(client_key_exchange, verbosity, TLS_param.cipher_suite.kx);
					free_handshake(client_key_exchange);

					if(verbosity>0)
						printf("\n>>> Change cipher spec\n");
					record_t* change_cipher_spec = make_change_cipher_spec();
					send_record(channel, change_cipher_spec);
					if(verbosity>1)
						print_record(change_cipher_spec);
					free_record(change_cipher_spec);

					if(verbosity!=0)
						printf("\n>>> Finished\n");
					handshake_t *finished = make_finished_message(&TLS_param);
					send_handshake(channel, finished);
					print_handshake(finished, verbosity, TLS_param.cipher_suite.kx);
					free_handshake(finished);
				}
				break;

			case FINISHED:
				if(TLS_param.previous_state == CHANGE_CIPHER_SPEC){
					if(verbosity>0)
						printf("\n<<< Finished\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);
					free_handshake(h);
					stop_channel(channel);
					break;
				}

			default:
				break;
		}
		free_handshake(h);
	}
}

/**
 * Do the handshake - client side.
 *
 *	\param to_send_cipher_suite_len: the number of cipher suites to add in the client hello
 *	\param to_send_cipher_suite: contains the choosen cipher suites for the client hello
 */
void do_client_handshake(int to_send_cipher_suite_len, cipher_suite_t to_send_cipher_suite[]) {

	// Setup the channel
	char *fileName = "TLSchannel.txt";
	char *channelFrom = "Client";
	char *channelTo = "Server";
	channel_t *client2server = create_channel(fileName, channelFrom, channelTo);
	set_on_receive(client2server, &onClientPacketReceive);

	TLS_param.previous_state = 0x0000;

	// Make client hello
	if(verbosity != 0)
		printf("\n>>> Client hello\n");
	handshake_t *client_hello = make_client_hello(TLS_param.client_random, to_send_cipher_suite, to_send_cipher_suite_len);
	print_handshake(client_hello,verbosity,TLS_param.cipher_suite.kx);

	send_handshake(client2server, client_hello);
	backup_handshake(&TLS_param,client_hello);
	free_handshake(client_hello);

	// Start channel and listener for new messages
	start_listener(client2server);
	wait_channel(client2server);

	// Clean up
	free(client2server);
}

/**
 * Function called from transport protocol
 * when a message is received by the server
 *
 *	\param channel: the communication channel
 *	\param p: the received packet
 */
void onServerPacketReceive(channel_t *channel, packet_transport_t *p){

	// Get record and print
	record_t *r = deserialize_record(p->message, p->length);
	if(r->type == CHANGE_CIPHER_SPEC){
		if(verbosity>1){
			printf("\n<<< Change CipherSpec\n");
			print_record(r);
		}
		// Clean up
		free_record(r);
		free_packet(p);
	}
	else if(r->type == HANDSHAKE){
		handshake_t *h = deserialize_handshake(r->message, r->length);

		// Clean up
		free_record(r);
		free_packet(p);

		switch (h->type) {
			case CLIENT_HELLO:
				if(TLS_param.previous_state == 0x00){
					TLS_param.previous_state = CLIENT_HELLO;
					backup_handshake(&TLS_param, h);
					server_client_hello_t *client_hello = deserialize_client_server_hello(h->message, h->length, CLIENT_MODE);
					if(verbosity>0)
						printf("\n<<< Client Hello\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);

					// Save client random
					memcpy(TLS_param.client_random, &(client_hello->random.UNIX_time), 4);
					memcpy(TLS_param.client_random+4, client_hello->random.random_bytes, 28);

					// Choose a cipher suite and send server hello
					if(verbosity>0)
						printf("\n>>> Server Hello\n");
					handshake_t * server_hello = make_server_hello(&TLS_param, client_hello);
					print_handshake(server_hello, verbosity, TLS_param.cipher_suite.kx);
					send_handshake(channel, server_hello);
					backup_handshake(&TLS_param, server_hello);
					free_handshake(server_hello);
					free_hello(client_hello);

					// Retrieve and send certificate
					if(verbosity>0)
						printf("\n>>> Certificate\n");
					handshake_t *certificate = make_certificate(&TLS_param);
					print_handshake(certificate, verbosity, TLS_param.cipher_suite.kx);
					send_handshake(channel, certificate);
					backup_handshake(&TLS_param, certificate);
					free_handshake(certificate);

					// Make server key exchange (if needed)
					if(TLS_param.cipher_suite.kx == DHE_KX || TLS_param.cipher_suite.kx == ECDHE_KX){
						handshake_t *server_key_exchange = make_server_key_exchange(&TLS_param);
						if(verbosity>0)
							printf("\n>>> Server key exchange\n");
						print_handshake(server_key_exchange, verbosity, TLS_param.cipher_suite.kx);
						send_handshake(channel, server_key_exchange);
						backup_handshake(&TLS_param, server_key_exchange);
						free_handshake(server_key_exchange);
					}

					// Make and send server hello done
					if(verbosity>0)
						printf("\n>>> Server hello done\n");
					handshake_t * server_hello_done = make_server_hello_done();
					print_handshake(server_hello_done, verbosity, TLS_param.cipher_suite.kx);
					send_handshake(channel, server_hello_done);
					backup_handshake(&TLS_param, server_hello_done);
					free_handshake(server_hello_done);

				}
				break;

			case CLIENT_KEY_EXCHANGE:
				if (TLS_param.previous_state == CLIENT_HELLO){
					TLS_param.previous_state = CLIENT_KEY_EXCHANGE;

					// Compute master key
					backup_handshake(&TLS_param, h);
					if(verbosity>0)
						printf("\n<<< Client Key Exchange\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);
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

					if(verbosity>0)
						printf("\n<<< Finished\n");
					print_handshake(h, verbosity, TLS_param.cipher_suite.kx);
					free_handshake(h);

					// Send ChangeCipherSpec
					if(verbosity>0)
						printf("\n>>> Change CipherSpec\n");
					record_t* change_cipher_spec = make_change_cipher_spec();
					send_record(channel, change_cipher_spec);
					if(verbosity>1)
						print_record(change_cipher_spec);
					free_record(change_cipher_spec);

					// Send Finished
					if(verbosity>0)
						printf("\n>>> Finished\n");
					handshake_t *finished = make_finished_message(&TLS_param);
					send_handshake(channel, finished);
					print_handshake(finished, verbosity, TLS_param.cipher_suite.kx);
					free_handshake(finished);

					stop_channel(channel);
				}
				break;

			default:
				break;
		}

		free_handshake(h);
	}
}

/**
 * Do the handshake - server side.
 */
void do_server_handshake() {
	// Setup the channel
	char *fileName = "TLSchannel.txt";
	char *channelFrom = "Server";
	char *channelTo = "Client";
	channel_t *server2client = create_channel(fileName, channelFrom, channelTo);
	set_on_receive(server2client, &onServerPacketReceive);

	TLS_param.previous_state = 0x00;

	// Start channel and listener for new messages
	start_listener(server2client);
	wait_channel(server2client);

	// Clean up
	free(server2client);
	CRYPTO_cleanup_all_ex_data();
}

/**
 * Free the TLS connection parameters.
 */
void free_tls_connection(){
	free(TLS_param.handshake_messages);
	free(TLS_param.master_secret);
	X509_free(TLS_param.server_certificate);
	free_server_key_exchange(TLS_param.server_key_ex, TLS_param.cipher_suite.kx);
	CRYPTO_cleanup_all_ex_data();
}
