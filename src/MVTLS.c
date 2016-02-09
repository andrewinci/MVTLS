/**
 *	SSL/TLS Project
 * 	\file MVTLS.c
 *
 *	Emulate a client or server for a TLS connection.
 *
 *	\date Created on 12/01/16.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include "TLS.h"

/** \def USAGE 
 * String with program arguments
 */
#define USAGE 	"MVTLS: TLS version 1.2 handshake\n"\
				"\n"\
				"Usage:\n"\
				" MVTLS (client | server) [args]\n"\
				"\n"\
				"Options:\n"\
				" Specify cipher suite id (not hex)\n"\
				"	-c	--cipher_id		[id]\n"\
				"\n"\
				" Specify cipher suite name\n"\
				"	-n	--name			[name]\n"\
				"\n"\
				" Specify key exchange\n"\
				"	-x	--key_exchange		(RSA|DHE|ECDHE)\n"\
				"\n"\
				" Specify authentication algorithm\n"\
				"	-a	--auth_algorithm	(RSA|DSS|ECDSA)\n"\
				"\n"\
				" Specify hash algorithm\n"\
				"	-h	--hash_algorithm	(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)\n"\
				"\n"\
				" Set verbosity\n"\
				"	-v				(0 final connection description - default\n"\
				"					|1 handshake binary\n"\
				"					|2 handshake binary and messages description\n"\
				"					|3 record binary and messages description)\n"\
				"\n"\
				" Show supported cipher suites\n"\
				"	-l	--list\n"\
				"\n"\
				" Show this help\n"\
				"	--help\n\n"

int main(int argc, char **argv) {

	// PARAMETERS
	int to_send_cipher_suite_len = 0;
	cipher_suite_t to_send_cipher_suite[NUM_CIPHER_SUITE];
	key_exchange_algorithm kx = NONE_KX;
	authentication_algorithm au = NONE_AU;
	hash_algorithm ha = NONE_H;

	if(argc == 2 && strcmp(argv[1], "--help") == 0){
		printf("%s", USAGE);
		return 0;
	}
	if(argc == 2 && (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0)){
		int num_added = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
		printf("Supported cipher suite are the following:\n");
		for(int i = 0; i<num_added; i++)
			printf("ID: %05d - name: %s\n", to_send_cipher_suite[i].cipher_id, to_send_cipher_suite[i].name);
		return 0;
	}

	if(argc<2 || (strcmp(argv[1], "server") !=0 && strcmp(argv[1], "client") != 0)){
		printf("Must set server or client.\n");
		printf("Try '--help' for more information.\n");
		return -1;
	}

	for(int i=2; i<argc; i+=2){
		if(strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cipher_id") == 0){
			cipher_suite_t c = get_cipher_suite_by_id(atoi(argv[i+1]));
			if(c.name != NULL){
				to_send_cipher_suite[to_send_cipher_suite_len] = c;
				to_send_cipher_suite_len++;
			}
			else{
				printf("Cannot parse %s %s or the requested cipher suite is not supported yet.\n",argv[i],argv[i+1]);
				return -1;
			}
		}
		else if(strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--name") == 0){
			cipher_suite_t c = get_cipher_suite_by_name(argv[i+1]);
			if(c.name != NULL){
				to_send_cipher_suite[to_send_cipher_suite_len] = c;
				to_send_cipher_suite_len++;
			}
			else{
				printf("Cannot parse %s %s or the requested cipher suite is not supported yet.\n",argv[i],argv[i+1]);
				return -1;
			}
		}
		else if(strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--key_exchange") == 0){
			if(strcmp("RSA", argv[i+1]) == 0)
				kx = RSA_KX;
			else if(strcmp("DHE", argv[i+1]) == 0)
				kx = DHE_KX;
			else if(strcmp("ECDHE", argv[i+1]) == 0)
				kx = ECDHE_KX;
			else{
				printf("Cannot parse %s %s or the requested key exchange is not supported yet.\n",argv[i],argv[i+1]);
				return -1;
			}
		}
		else if(strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--auth_algorithm") == 0){
			if(strcmp("RSA", argv[i+1]) == 0)
				au = RSA_AU;
			else if(strcmp("DSS", argv[i+1]) == 0)
				au = DSS_AU;
			else if(strcmp("ECDSA", argv[i+1]) == 0)
				au = ECDSA_AU;
			else{
				printf("Cannot parse %s %s or the requested authentication algorithm is not supported yet.\n",argv[i],argv[i+1]);
				return -1;
			}
		}
		else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hash_algorithm") == 0){
			if(strcmp("MD5", argv[i+1]) == 0)
				ha = MD5_H;
			else if(strcmp("SHA1", argv[i+1]) == 0)
				ha = SHA1_H;
			else if(strcmp("SHA224", argv[i+1]) == 0)
				ha = SHA224_H;
			else if(strcmp("SHA256", argv[i+1]) == 0)
				ha = SHA256_H;
			else if(strcmp("SHA384", argv[i+1]) == 0)
				ha = SHA384_H;
			else if(strcmp("SHA512", argv[i+1]) == 0)
				ha = SHA512_H;
			else{
				printf("Cannot parse %s %s or the requested hash function is not supported yet.\n",argv[i],argv[i+1]);
				return -1;
			}
		}
		else if(strcmp(argv[i], "-v") == 0 ){
			argv[i+1][0]+=0x01;
			verbosity = atoi(argv[i+1]);
			verbosity--;
			if(verbosity<0 || verbosity>3){
				argv[i+1][0]-=0x01;
				printf("Invalid option '%s %s'\n", argv[i], argv[i+1]);
				printf("Try '--help' for more information.\n");
				return -1;
			}
		}
        else{
			printf("Invalid option '%s'\n",argv[i]);
			printf("Try '--help' for more information.\n");
			return -1;
		}
	}

	if(strcmp(argv[1], "server") == 0){
		printf("\n*** TLS server is started ***\n");
		do_server_handshake();
	}
	else if(strcmp(argv[1], "client") == 0){
		printf("\n*** TLS client is started ***\n");
		// If no option is set, load all cipher suite
		if(to_send_cipher_suite_len == 0 && kx == NONE_KX && au == NONE_AU && ha == NONE_H){
		to_send_cipher_suite_len = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
		printf("All supported cipher suites are loaded.\n");
		printf("Try --help for more information.\n");
	}
	else if (to_send_cipher_suite_len == 0){
		int num_added = get_cipher_suites(kx, ha, au, to_send_cipher_suite+to_send_cipher_suite_len);
		to_send_cipher_suite_len+=num_added;
		if(to_send_cipher_suite_len == 0){
			printf("No supported cipher suite with the selected arguments.\n");
			printf("%s", USAGE);
			return -1;
		}
	}
		do_client_handshake(to_send_cipher_suite_len, to_send_cipher_suite);
	}

	// Print details about connection
	printf("\nServer random:\n");
	for(int i=0;i<32;i++)
		printf("%02x ",connection_parameters.server_random[i]);
	printf("\nClient random:\n");
	for(int i=0;i<32;i++)
		printf("%02x ",connection_parameters.client_random[i]);
	printf("\nCertificate details:\n");
	printf("%s",connection_parameters.server_certificate->name);
	printf("\nCipher suite: %s\n",connection_parameters.cipher_suite.name);
	printf("\nMaster key: \n");
	for(int i=0;i<connection_parameters.master_secret_len;i++)
		printf("%02x ",connection_parameters.master_secret[i]);
	printf("\n");

	// Clean up
	free_tls_connection();
}
