/**
 *	SSL/TLS Project
 *	\file ServerKeyExchange.c
 *
 *	This file contains functions to manage the server key exchange
 *	and respective structs.
 *
 *	\date Created on 03/01/16.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifdef MAKEFILE
#include "HandshakeMessages/ServerKeyExchange.h"
#else
#include "ServerKeyExchange.h"
#endif

            /************ SING VERIFY *****************/

/**
 * Use the private key ../certificates/serverDSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeded, -1 if an error occurred
 */
int sign_with_DSS(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type){
    // Get private key for sign
    FILE *private_key_file = fopen("../certificates/serverDSA.key", "r");
    if (!private_key_file) {
        fprintf(stderr, "Unable to open DSA private key file, store it in ../certificates/serverDSA.key\n");
        exit(-1);
    }
    
    DSA *dsa_private = PEM_read_DSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    
    // Allocate memory for signature
    *signature = malloc(sizeof(unsigned char)*DSA_size(dsa_private));
    
    int res = DSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, dsa_private );
    
    DSA_free(dsa_private);
    
    return res;
}

/**
 * Use the private key ../certificates/serverRSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeded, -1 if an error occurred
 */
int sign_with_RSA(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type) {
    // Get private key from file
    int res;
    RSA *rsa_private = NULL;
    FILE *fp;
    
    if((fp= fopen("../certificates/serverRSA.key", "r")) != NULL){
        rsa_private=PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        if(rsa_private==NULL){
            printf("\nUnable to open RSA private key, store it in ../certificates/serverRSA.key\n");
            exit(-1);
        }
    }
    fclose(fp);
    
    // Allocate memory for signature
    *signature = malloc(sizeof(unsigned char)*RSA_size(rsa_private));
    
    res = RSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, rsa_private);
    
    RSA_free(rsa_private);
    
    return res;
}

/**
 * Use the private key ../certificates/serverECDSA.key to sign a message
 *
 *	\param signature: a pointer to NULL, will return the computed signature
 *	\param signature_length: return the signature length
 *	\param to_sign_len: the message length to sign
 *	\param to_sign: the message to sign
 *	\param sign_type: specify the message type (for OpenSSL support)
 *	\return 1 if the sign succeeced, -1 if an error occurred
 */
int sign_with_ECDSA(unsigned char **signature, unsigned int *signature_length, unsigned int to_sign_len, unsigned char *to_sign, int sign_type){
    int res;
    EC_KEY *ecdsa_private;
    // Get private key for sign
    FILE *private_key_file = fopen("../certificates/serverECDSA.key", "r");
    if (!private_key_file) {
        fprintf(stderr, "\nUnable to open ECDSA private key file, store it in ../certificates/serverECDSA.key\n");
        exit(-1);
    }
    
    ecdsa_private = PEM_read_ECPrivateKey(private_key_file, NULL, NULL, NULL);
    
    fclose(private_key_file);
    
    // Allocate memory for signature
    *signature = malloc(sizeof(unsigned char)*ECDSA_size(ecdsa_private));
    
    res = ECDSA_sign(sign_type, to_sign, to_sign_len, *signature, signature_length, ecdsa_private );
    
    EC_KEY_free(ecdsa_private);
    
    return res;
}

/**
 * Sign the server_key_exchange message for a DHE key exchange.
 * The function chooses an arbitrary hash algorithm for the signature (except MD5, SHA-1).
 * It takes private key in ../certificates/ folder with name serverA.key where A can be RSA, DSS.
 *
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to sign.
 *	\param au: the authentication algorithm.
 */
int sign_DHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au) {
    
    // Extract p, g, pubkey
    int p_len;
    unsigned char *p = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->p));
    p_len = BN_bn2bin(server_key_ex->p, p);
    
    int g_len;
    unsigned char *g = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->g));
    g_len = BN_bn2bin(server_key_ex->g, g);
    
    int pubkey_len;
    unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pubKey));
    pubkey_len = BN_bn2bin(server_key_ex->pubKey, pubkey_char);
    
    // Choose random hash alg
    srand((int)time(NULL));
    hash_algorithm sign_hash_alg = rand()%4+3;
    server_key_ex->sign_hash_alg = sign_hash_alg+(au<<8);
    
    int sign_type;
    const EVP_MD *hash;
    switch (sign_hash_alg) {
        case SHA224_H:
            sign_type = NID_sha224;
            hash = EVP_sha224();
            break;
        case SHA256_H:
            sign_type = NID_sha256;
            hash = EVP_sha256();
            break;
        case SHA384_H:
            sign_type = NID_sha384;
            hash = EVP_sha384();
            break;
        case SHA512_H:
            sign_type = NID_sha512;
            hash = EVP_sha512();
            break;
        default:
            printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
            exit(-1);
    }
    
    // Compute hash
    unsigned char hash_digest[hash->md_size];
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, hash, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, p, p_len);
    EVP_DigestUpdate(mdctx, g, g_len);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
    EVP_MD_CTX_destroy(mdctx);
    
    int result = 0;
    
    switch (au) {
        case RSA_AU:
            result = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
            break;
        case DSS_AU:
            result = sign_with_DSS(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
            break;
        default:
            printf("\nError in sign_DHE_server_key_ex\n");
            exit(-1);
    }
    
    free(p);
    free(g);
    free(pubkey_char);
    
    return result;
}

/**
 * Sign the server_key_exchange message for a ECDHE key exchange.
 * The function chooses an arbitrary hash algorithm for the signature (except MD5, SHA-1).
 * It takes private key in ../certificates/ folder with name serverA.key where A can be RSA, ECDSA.
 *
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to sign.
 *	\param au: the authentication algorithm.
 */
int sign_ECDHE_server_key_ex(unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au){
    
    // RFC 4492
    int pubkey_len;
    unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pub_key));
    pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);
    
    // Choose random hash alg
    srand((int)time(NULL));
    hash_algorithm sign_hash_alg = rand()%4+3;
    server_key_ex->sign_hash_alg = sign_hash_alg+(au<<8);
    
    int sign_type;
    const EVP_MD *hash;
    switch (sign_hash_alg) {
        case SHA224_H:
            sign_type = NID_sha224;
            hash = EVP_sha224();
            break;
        case SHA256_H:
            sign_type = NID_sha256;
            hash = EVP_sha256();
            break;
        case SHA384_H:
            sign_type = NID_sha384;
            hash = EVP_sha384();
            break;
        case SHA512_H:
            sign_type = NID_sha512;
            hash = EVP_sha512();
            break;
        default:
            printf("\nError in recognize hash for signature or too low level of security in server_key_ex\n");
            exit(-1);
    }
    
    // Compute hash
    unsigned char hash_digest[hash->md_size];
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, hash, NULL);
    EVP_DigestUpdate(mdctx, client_random, 32);
    EVP_DigestUpdate(mdctx, server_random, 32);
    EVP_DigestUpdate(mdctx, &server_key_ex->named_curve, 2);
    EVP_DigestUpdate(mdctx, pubkey_char, pubkey_len);
    EVP_DigestFinal_ex(mdctx, hash_digest, NULL);
    EVP_MD_CTX_destroy(mdctx);
    
    int res=0;
    switch (au) {
        case RSA_AU:
            res = sign_with_RSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
            break;
        case ECDSA_AU:
            res = sign_with_ECDSA(&server_key_ex->signature, &server_key_ex->signature_length, hash->md_size, hash_digest, sign_type);
        default:
            break;
    }
    
    free(pubkey_char);
    
    return res;
}


				/******* SERVER KEY EXCHANGE *******/
/**
 * Make the server key exchange for DHE key exchange.
 * It computes the DH parameters and save the message in the
 * connection parameters TLS_param.
 *
 *	\param TLS_param: connection parameters
 *	\return the dhe_server_key_exchange struct
 */
dhe_server_key_exchange_t * make_DHE_server_key_exchange(handshake_parameters_t *TLS_param){
    
    // Diffie-Hellman server key exchange
    // Generate ephemeral Diffie-Hellman parameters
    DH *privkey;
    int codes;
    if((privkey = DH_new()) == NULL){
        printf("\nError in DH_new\n");
        exit(-1);
    }
    if(DH_generate_parameters_ex(privkey, 512, DH_GENERATOR_2 , NULL) != 1){
        printf("\nError in DH_generate_parameters\n");
        exit(-1);
    }
    if(DH_check(privkey, &codes) != 1){
        printf("\nError in DH_check\n");
        exit(-1);
    }
    if(codes != 0){
        printf("\nDH_check failed\n");
        exit(-1);
    }
    // Generate the public and private keys pair
    if(DH_generate_key(privkey) != 1){
        printf("\nError in DH_generate_key\n");
        exit(-1);
    }
    
    // Set server key exchange parameters
    dhe_server_key_exchange_t *server_key_ex = malloc(sizeof(dhe_server_key_exchange_t));
    server_key_ex->g = BN_dup(privkey->g);
    server_key_ex->p = BN_dup(privkey->p);
    server_key_ex->pubKey = BN_dup(privkey->pub_key);
    
    // Add signature and set hash algorithm
    sign_DHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);
    
    // Save parameters
    TLS_param->server_key_ex = server_key_ex;
    TLS_param->private_key = BN_dup(privkey->priv_key);
    
    // Clean up
    DH_free(privkey);
    
    return server_key_ex;
}

/**
 * Make the server key exchange for ECDHE key exchange.
 * It computes the ECDHE parameters using the secp256k1 curve and save the message in the
 * connection parameters TLS_param.
 *
 *	\param TLS_param: connection parameters
 *	\return the ecdhe_server_key_exchange struct
 */
ecdhe_server_key_exchange_t * make_ECDHE_server_key_exchange(handshake_parameters_t *TLS_param){
    
    // Elliptic cruve Diffie-Hellman server key exchange
    // Generate ephemeral Diffie-Hellman parameters
    EC_KEY *key;
    uint16_t curve_name = NID_secp256k1;
    // Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve
    if((key = EC_KEY_new_by_curve_name(curve_name)) == NULL){
        printf("\nError in setting EC parameters\n");
        exit(-1);
    }
    // Generate the private and public keys
    if(EC_KEY_generate_key(key) != 1){
        printf("\nError in generate EC keys\n");
        exit(-1);
    }
    
    // Set server key exchange parameters
    ecdhe_server_key_exchange_t *server_key_ex = malloc(sizeof(ecdhe_server_key_exchange_t));
    server_key_ex->named_curve = curve_name;
    server_key_ex->pub_key = BN_new();
    EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, server_key_ex->pub_key, NULL);
    
    // Add signature
    sign_ECDHE_server_key_ex(TLS_param->client_random, TLS_param->server_random, server_key_ex, TLS_param->cipher_suite.au);
    
    // Save parameters
    TLS_param->server_key_ex = server_key_ex;
    TLS_param->private_key = BN_dup(EC_KEY_get0_private_key(key));
    
    // Clean up
    EC_KEY_free(key);
    
    return server_key_ex;
}

/**
 * Make the server key exchange handshake message.
 * The function also sets the message in the connection parameters
 * to compute the master key in the client key exchange message.
 *
 *	\param TLS_param: connection parameters
 *	\return the server key exchange handshake message
 */
handshake_t * make_server_key_exchange(handshake_parameters_t *TLS_param){
    
    // Initialize server key exchange
    void *server_key_ex = NULL;
    
    // Make server key exchange packet
    switch (TLS_param->cipher_suite.kx){
        case DHE_KX:
            server_key_ex = (dhe_server_key_exchange_t *)make_DHE_server_key_exchange(TLS_param);
            break;
        case ECDHE_KX:
            server_key_ex = (ecdhe_server_key_exchange_t *)make_ECDHE_server_key_exchange(TLS_param);
            break;
        default:
            printf("\nError in make_server_key_exchange, key exchange algorithm not recognized\n");
            exit(-1);
    }
    
    // Insert server key exchange into handshake packet
    handshake_t *server_key_ex_h = malloc(sizeof(handshake_t));
    server_key_ex_h->type = SERVER_KEY_EXCHANGE;
    serialize_server_key_exchange(server_key_ex, &server_key_ex_h->message, &server_key_ex_h->length, TLS_param->cipher_suite.kx);
    
    // Save parameters
    TLS_param->server_key_ex = server_key_ex;
    
    return server_key_ex_h;
}


/**
 * Serialize a server key exchange message into a byte stream.
 * 
 *	\param server_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 *	\param kx: the key exchange method of the handshake
 */
void serialize_server_key_exchange(server_key_exchange_t *server_key_exchange, unsigned char **stream, uint32_t *streamLen, key_exchange_algorithm kx){

	unsigned char *result;
	uint16_t len;

	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = (dhe_server_key_exchange_t*)server_key_exchange;
		int pLen = BN_num_bytes(server_key_ex->p), gLen = BN_num_bytes(server_key_ex->g), pubKeyLen = BN_num_bytes(server_key_ex->pubKey);

		*streamLen = 2+pLen+2+gLen+2+pubKeyLen+2+2+server_key_ex->signature_length;
		result = malloc(sizeof(unsigned char)*(*streamLen));
		*stream = result;

		pLen = REV16(pLen);
		memcpy(result, &pLen, 2);
		result+=2;
		len = BN_bn2bin(server_key_ex->p, result);
		result+=len;

		gLen = REV16(gLen);
		memcpy(result, &gLen, 2);
		result+=2;

		len = BN_bn2bin(server_key_ex->g, result);
		result+=len;

		pubKeyLen = REV16(pubKeyLen);
		memcpy(result, &pubKeyLen, 2);
		result+=2;

		len = BN_bn2bin(server_key_ex->pubKey, result);
		result+=len;

		// Add signature
		memcpy(result, &(server_key_ex->sign_hash_alg), 2);
		result+=2;

		len = server_key_ex->signature_length;
		len = REV16(len);
		memcpy(result, &len, 2);
		result+=2;

		memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
	}
	else if(kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = (ecdhe_server_key_exchange_t*)server_key_exchange;
		// Compute stream len
		// named_curve(1) curve_name(2) pub_key_len(1) pub_key(..) signature_alg(2) signature_len(2) siganture(..)
		*streamLen = 1 + 2 + 1 + BN_num_bytes(server_key_ex->pub_key) + 2 + 2 + server_key_ex->signature_length;

		result = malloc(sizeof(unsigned char)*(*streamLen));
		*stream = result;

		// Set named_curve mode
		*result = 0x03;
		result++;

		// Set curve name
		uint16_t curve_name = server_key_ex->named_curve;
		curve_name = REV16(curve_name);
		memcpy(result, &curve_name, sizeof(uint16_t));
		result+=2;

		// Convert and set public key
		*result = BN_num_bytes(server_key_ex->pub_key);
		result++;

		BN_bn2bin(server_key_ex->pub_key, result);
		result+=BN_num_bytes(server_key_ex->pub_key);

		// Add signature
		memcpy(result, &(server_key_ex->sign_hash_alg), 2);
		result+=2;

		len = REV16(server_key_ex->signature_length);
		memcpy(result, &len, 2);
		result+=2;

		memcpy(result, server_key_ex->signature, server_key_ex->signature_length);
	}
}

/**
 * De-serialize a server key exchange byte stream message into the appropriate 
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\param kx: the key exchange method of the handshake
 *	\return the de-serialized server_key_exchange message.
 */
server_key_exchange_t *deserialize_server_key_exchange(unsigned char *message, uint32_t message_len, key_exchange_algorithm kx){
	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = malloc(sizeof(dhe_server_key_exchange_t));
		uint16_t len;

		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->p = BN_bin2bn(message, len, NULL);
		message+=len;
		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->g = BN_bin2bn(message, len, NULL);
		message+=len;
		memcpy(&len, message, 2);
		message+=2;

		len = REV16(len);
		server_key_ex->pubKey = BN_bin2bn(message, len, NULL);
		message+=len;

		memcpy(&(server_key_ex->sign_hash_alg), message, 2);
		message+=2;

		memcpy(&(server_key_ex->signature_length), message, 2);
		message+=2;

		server_key_ex->signature_length = REV16(server_key_ex->signature_length);
		server_key_ex->signature = malloc(sizeof(unsigned char)*server_key_ex->signature_length);
		memcpy(server_key_ex->signature, message, server_key_ex->signature_length);

		return (server_key_exchange_t*)server_key_ex;
	}
	else if (kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = malloc(sizeof(ecdhe_server_key_exchange_t));
		message++; // we already know that it is 0x03 for named_curve
		uint16_t curve_name;
		memcpy(&curve_name, message, sizeof(char)*2);
		server_key_ex->named_curve = REV16(curve_name);
		message+=2;

		uint8_t pubkey_len = *message;
		message++;
		server_key_ex->pub_key = BN_bin2bn(message, pubkey_len, NULL);
		message+=pubkey_len;

		memcpy(&(server_key_ex->sign_hash_alg), message, 2);
		message+=2;

		memcpy(&(server_key_ex->signature_length), message, 2);
		message+=2;

		server_key_ex->signature_length = REV16(server_key_ex->signature_length);
		server_key_ex->signature = malloc(sizeof(unsigned char)*server_key_ex->signature_length);
		memcpy(server_key_ex->signature, message, server_key_ex->signature_length);

		return (server_key_exchange_t*)server_key_ex;
	}

	return NULL;
}

/**
 * Print details about the server key exchange message
 *
 *	\param server_key_exchange: the message to print
 *	\param kx: the key exchange method of the handshake
 */
void print_server_key_exchange(server_key_exchange_t *server_key_exchange, key_exchange_algorithm kx){

	char *pubkey_char = NULL;

	if(kx == DHE_KX){
		dhe_server_key_exchange_t *server_key_ex = (dhe_server_key_exchange_t *) server_key_exchange;
		// Extract p, g, pubkey
		char *p = NULL;
		p = BN_bn2hex(server_key_ex->p);

		char *g = NULL;
		g = BN_bn2hex(server_key_ex->g);

		pubkey_char = BN_bn2hex(server_key_ex->pubKey);

		printf("** DHE parameters **\n");
		printf(" p: %s",p);
		printf("\n g: %s",g);
		printf("\n Public key: %s",pubkey_char);

		printf("\n Signature hash algorithm: %04x", server_key_ex->sign_hash_alg);
		printf("\n Signature: ");
		for(int i =0;i<server_key_ex->signature_length; i++)
			printf("%02X ", server_key_ex->signature[i]);
		printf("\n");

		OPENSSL_free(p);
		OPENSSL_free(g);
	}
	else if (kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *server_key_ex = (ecdhe_server_key_exchange_t *) server_key_exchange;

		pubkey_char = BN_bn2hex(server_key_ex->pub_key);

		printf("** ECDHE parameters **\n");
		printf(" Curve type: named_curve");
		printf("\n Named curve: %04X", server_key_ex->named_curve);
		printf("\n Public key: %s",pubkey_char);

		printf("\n Signature hash algorithm: %04x", server_key_ex->sign_hash_alg);
		printf("\n Signature: ");
		for(int i =0;i<server_key_ex->signature_length; i++)
			printf("%02X ", server_key_ex->signature[i]);
		printf("\n");
	}

	OPENSSL_free(pubkey_char);
}

/**
 * Dealloc memory of server key exchange.
 * 
 *	\param server_key_ex: the server key exchange message to deallocate
 *	\param kx: the key exchange method of the handshake
 */
void free_server_key_exchange(server_key_exchange_t *server_key_ex, key_exchange_algorithm kx){
	if(server_key_ex != NULL && kx == DHE_KX){
		dhe_server_key_exchange_t *params = (dhe_server_key_exchange_t*)server_key_ex;
		BN_free(params->g);
		BN_free(params->p);
		BN_free(params->pubKey);
		free(params->signature);
		free(params);
	}
	else if(server_key_ex != NULL && kx == ECDHE_KX){
		ecdhe_server_key_exchange_t *params = (ecdhe_server_key_exchange_t*) server_key_ex;
		free(params->signature);
		BN_free(params->pub_key);
		free(server_key_ex);
	}
}

