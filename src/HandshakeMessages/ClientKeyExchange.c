/**
 *	SSL/TLS Project
 *	\file ClientKeyExchange.c
 *
 *	This file contains functions to manage the client key exchange
 *	and respective structs.
 *
 *	\date Created on 03/01/16.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 */

#ifdef MAKEFILE
#include "HandshakeMessages/ClientKeyExchange.h"
#else
#include "ClientKeyExchange.h"
#endif

/**
 * Verify the server_key_exchange message for a DHE key exchange.
 *
 *	\param certificate: the certificate to use to verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_DHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, dhe_server_key_exchange_t *server_key_ex, authentication_algorithm au) {
    
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
    
    // Get hash function from packet
    hash_algorithm sign_hash_alg = (server_key_ex->sign_hash_alg) & 0x00FF;
    
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
    if(au == RSA_AU){
        EVP_PKEY *pubkey = NULL;
        RSA *rsa = NULL;
        pubkey = X509_get_pubkey(certificate);
        rsa = EVP_PKEY_get1_RSA(pubkey);
        result = RSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, rsa);
        EVP_PKEY_free(pubkey);
        RSA_free(rsa);
    }
    else if(au == DSS_AU){
        EVP_PKEY *pubkey = NULL;
        DSA *dsa = NULL;
        pubkey = X509_get_pubkey(certificate);
        dsa = EVP_PKEY_get1_DSA(pubkey);
        result = DSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, dsa);
        EVP_PKEY_free(pubkey);
        DSA_free(dsa);
    }
    
    // Clean up
    free(p);
    free(g);
    free(pubkey_char);
    
    return result;
}


/**
 * Verify the server_key_exchange message for a ECDHE key exchange.
 *
 *	\param certificate: the certificate to use for verify the signature
 *	\param client_random: the random sent by the client in the client hello. Must point to 32 byte stream
 *	\param server_random: the random sent by the server in the server hello. Must point to 32 byte stream
 *	\param server_key_ex: the server key exchange message to verify.
 *	\param au: the authentication algorithm.
 */
int verify_ECDHE_server_key_ex_sign(X509 *certificate, unsigned char *client_random, unsigned char *server_random, ecdhe_server_key_exchange_t *server_key_ex, authentication_algorithm au){
    
    int pubkey_len;
    unsigned char *pubkey_char = malloc(sizeof(unsigned char)*BN_num_bytes(server_key_ex->pub_key));
    pubkey_len = BN_bn2bin(server_key_ex->pub_key, pubkey_char);
    
    // Get hash function from packet
    hash_algorithm sign_hash_alg = (server_key_ex->sign_hash_alg) & 0x00FF;
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
    
    int result = 0;
    if(au == RSA_AU){
        EVP_PKEY *pubkey = NULL;
        RSA *rsa = NULL;
        pubkey = X509_get_pubkey(certificate);
        rsa = EVP_PKEY_get1_RSA(pubkey);
        result = RSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, rsa);
        EVP_PKEY_free(pubkey);
        RSA_free(rsa);
    }
    else if(au == ECDSA_AU){
        EVP_PKEY *pubkey = NULL;
        EC_KEY *ecdsa = NULL;
        pubkey = X509_get_pubkey(certificate);
        ecdsa = EVP_PKEY_get1_EC_KEY(pubkey);
        result = ECDSA_verify(sign_type, hash_digest, hash->md_size, server_key_ex->signature, server_key_ex->signature_length, ecdsa);
        EVP_PKEY_free(pubkey);
        EC_KEY_free(ecdsa);
    }
    
    free(pubkey_char);
    
    return result;
}

/******* CLIENT KEY EXCHANGE *******/

/**
 * Make the client key exchange message for RSA key exchange.
 * This function is called from make_client_key_exchange if the key exchange is RSA.
 *
 *	\param client_key_ex: the client key exchange message
 *	\param TLS_param: the connection parameters
 */
void make_RSA_client_key_exchange(handshake_parameters_t *TLS_param, client_key_exchange_t *client_key_ex){
    
    // Initialize pre master key
    int pre_master_key_len = 58;
    unsigned char *pre_master_key = calloc(pre_master_key_len, 1);
    
    uint16_t temp = REV16(TLS_param->tls_version);
    memcpy(pre_master_key, &temp, 2);
    
    // Copy random
    RAND_pseudo_bytes(pre_master_key+2, 46);
    unsigned char seed[64];
    memcpy(seed, TLS_param->client_random, 32);
    memcpy(seed+32, TLS_param->server_random, 32);
    
    // Set hash function
    const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);
    TLS_param->master_secret_len = 48;
    
    // Compute and set pre master key
    PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);
    
    // Initialize and set RSA parameters from certificate
    EVP_PKEY *pubkey = NULL;
    RSA *rsa = NULL;
    
    pubkey = X509_get_pubkey(TLS_param->server_certificate);
    rsa = EVP_PKEY_get1_RSA(pubkey);
    
    // Encrypt pre master key
    unsigned char *pre_master_key_enc = malloc(sizeof(unsigned char)*256);
    int pre_master_key_enc_len = 0;
    pre_master_key_enc_len = RSA_public_encrypt(pre_master_key_len, pre_master_key, pre_master_key_enc, rsa, RSA_PKCS1_PADDING);
    
    // Set parameters in client key exchange packet
    client_key_ex->key = pre_master_key_enc;
    client_key_ex->key_length = pre_master_key_enc_len;
    
    // Clean up
    EVP_PKEY_free(pubkey);
    RSA_free(rsa);
    free(pre_master_key);
}

/**
 * Make the client key exchange message for DHE key exchange.
 * This function is called from make_client_key_exchange if the key exchange is DHE.
 *
 *	\param client_key_ex: the client key exchange message
 *	\param TLS_param: the connection parameters
 */
void make_DHE_client_key_exchange(handshake_parameters_t *TLS_param, client_key_exchange_t *client_key_ex){
    
    // Set server key exchange type
    dhe_server_key_exchange_t *server_key_exchange = (dhe_server_key_exchange_t*)TLS_param->server_key_ex;
    
    // Verify signature
    if(verify_DHE_server_key_ex_sign(TLS_param->server_certificate, TLS_param->client_random, TLS_param->server_random, server_key_exchange,TLS_param->cipher_suite.au) == 0){
        printf("\nError in make_DHE_client_key_exchange, signature not valid\n");
        exit(-1);
    }
    printf("\nSignature is valid\n");
    
    // Initialize and set Diffie-Hellman parameters
    DH *dh_key = DH_new();
    dh_key->g = BN_dup(server_key_exchange->g);
    dh_key->p = BN_dup(server_key_exchange->p);
    if(DH_generate_key(dh_key) != 1){
        printf("\nError in DH_generate_key\n");
        exit(-1);
    }
    
    // Initialize pre master key
    unsigned char *pre_master_key = malloc(DH_size(dh_key));
    int pre_master_key_len = 0;
    pre_master_key_len = DH_compute_key(pre_master_key, server_key_exchange->pubKey, dh_key);
    
    // Copy random
    unsigned char seed[64];
    memcpy(seed, TLS_param->client_random, 32);
    memcpy(seed+32, TLS_param->server_random, 32);
    
    // Set hash function
    const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);
    
    // Initialize and comput pre master key
    TLS_param->master_secret_len = 48;
    PRF(hash_function, pre_master_key, pre_master_key_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);
    
    // Set client key exchange parameters
    client_key_ex->key_length = BN_num_bytes(dh_key->pub_key);
    client_key_ex->key = malloc(sizeof(unsigned char)*client_key_ex->key_length);
    BN_bn2bin(dh_key->pub_key, client_key_ex->key);
    
    // Clean up
    DH_free(dh_key);
    free(pre_master_key);
}

/**
 * Make the client key exchange message for ECDHE key exchange.
 * This function is called from make_client_key_exchange if the key exchange is ECDHE.
 *
 *	\param client_key_ex: the client key exchange message
 *	\param TLS_param: the connection parameters
 */
void make_ECDHE_client_key_exchange(handshake_parameters_t *TLS_param, client_key_exchange_t *client_key_ex){
    
    // Set server key exchange algorithm
    ecdhe_server_key_exchange_t *server_key_exchange = (ecdhe_server_key_exchange_t * )TLS_param->server_key_ex;
    
    // Verify signature
    if(verify_ECDHE_server_key_ex_sign(TLS_param->server_certificate, TLS_param->client_random, TLS_param->server_random, server_key_exchange,TLS_param->cipher_suite.au)<1){
        printf("\nError in make_ECDHE_client_key_exchange, signature not valid\n");
        exit(-1);
    }
    printf("\nSignature is valid\n");
    
    // Initialize and set elliptic curve Diffie-Hellman parameters
    EC_KEY *key = EC_KEY_new_by_curve_name(server_key_exchange->named_curve);
    if(EC_KEY_generate_key(key) != 1){
        printf("\nError in make_ECDHE_client_key_exchange, EC_KEY_generate\n");
        exit(-1);
    }
    EC_POINT *pub_key_point = EC_POINT_bn2point(EC_KEY_get0_group(key), server_key_exchange->pub_key, NULL, NULL);
    
    // Initialize pre master secret
    int field_size, pre_master_len;
    unsigned char *pre_master;
    
    // Calculate size of buffer for shared secret
    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    pre_master_len = (field_size+7)/8;
    // Allocate memory for shared secret
    pre_master = malloc(sizeof(unsigned char)*pre_master_len);
    // Derive shared secret
    ECDH_compute_key(pre_master, pre_master_len, pub_key_point, key, NULL);
    
    // Copy random
    unsigned char seed[64];
    memcpy(seed, TLS_param->client_random, 32);
    memcpy(seed+32, TLS_param->server_random, 32);
    
    // Get hash function
    const EVP_MD *hash_function = get_hash_function(TLS_param->cipher_suite.hash);
    
    // Initialize and compute pre master secret
    TLS_param->master_secret_len = 48;
    PRF(hash_function, pre_master, pre_master_len, "master secret", seed, 64, TLS_param->master_secret_len, &TLS_param->master_secret);
    
    // Compute client key exchange parameters
    BIGNUM *pub_key = BN_new();
    EC_POINT_point2bn(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, pub_key, NULL);
    
    // Set client key exchange parameters
    client_key_ex->key_length = BN_num_bytes(pub_key);
    client_key_ex->key = malloc(sizeof(unsigned char)*client_key_ex->key_length);
    BN_bn2bin(pub_key, client_key_ex->key);
    
    // Clean up
    BN_free(pub_key);
    EC_POINT_free(pub_key_point);
    EC_KEY_free(key);
    free(pre_master);
}

/**
 * Given the information in TLS_parameter and the key exchange algorithm
 * return the handshake of the client key exchange. That includes to compute the
 * pre-master key. It also computes the master secret and set it in TLS_param.
 *
 *	\param TLS_param: the parameters of the connection
 *	\param key_ex_alg: the key exchange algorithm of the handshake
 *	\return the client key exchange handshake message
 */
handshake_t * make_client_key_exchange(handshake_parameters_t *TLS_param, uint16_t key_ex_alg){
    
    // Initialize handshake packet and client key exchange message
    handshake_t *client_key_exchange_h = malloc(sizeof(handshake_t));
    client_key_exchange_h->type = CLIENT_KEY_EXCHANGE;
    client_key_exchange_t *client_key_exchange = malloc(sizeof(client_key_exchange_t));
    
    switch (TLS_param->cipher_suite.kx){
        case RSA_KX:
            make_RSA_client_key_exchange(TLS_param, client_key_exchange);
            break;
        case DHE_KX:
            make_DHE_client_key_exchange(TLS_param, client_key_exchange);
            break;
        case ECDHE_KX:
            make_ECDHE_client_key_exchange(TLS_param, client_key_exchange);
            break;
        default:
            printf("\nError in make_client_key_exchange\n");
            exit(-1);
    }
    
    serialize_client_key_exchange(client_key_exchange, &(client_key_exchange_h->message), (&client_key_exchange_h->length));
    
    // Clean up
    free_client_key_exchange(client_key_exchange);
    
    return client_key_exchange_h;
}

/**
 * Serialize a client key exchange message into a byte stream.
 *
 *	\param client_key_exchange: the message to serialize
 *	\param stream: a pointer to NULL. Will contain the serialization result
 *	\param streamLen: the serialization result length
 */
void serialize_client_key_exchange(client_key_exchange_t *client_key_exchange, unsigned char **stream, uint32_t *streamLen){
    // The first 2 message byte are the key length
    unsigned char *buff = malloc(sizeof(unsigned char)*(client_key_exchange->key_length+2));
    *stream = buff;
    // Add lenght
    uint16_t temp = REV16(client_key_exchange->key_length);
    memcpy(buff, &temp, 2);
    buff+=2;
    // Add key
    memcpy(buff, client_key_exchange->key, client_key_exchange->key_length);
    *streamLen=client_key_exchange->key_length+2;
}

/**
 * De-serialize a client key exchange byte stream message into the appropriate
 * server_key_excahnge message (DHE, ECDHE)
 *
 *	\param message: the byte stream message to de-serialize
 *	\param message_len: the byte stream length
 *	\return the de-serialized client key exchange message
 */
client_key_exchange_t *deserialize_client_key_exchange(unsigned char *message, uint32_t message_len){
    client_key_exchange_t *rsa_server_key_ex = malloc(sizeof(client_key_exchange_t));
    memcpy(&(rsa_server_key_ex->key_length), message, 2);
    message+=2;
    
    rsa_server_key_ex->key_length = REV16(rsa_server_key_ex->key_length);
    
    unsigned char *buff = malloc(sizeof(unsigned char)*rsa_server_key_ex->key_length);
    rsa_server_key_ex->key = buff;
    memcpy(buff, message, rsa_server_key_ex->key_length);
    
    return rsa_server_key_ex;
}

/**
 * Print details about the client key exchange message
 *
 *	\param client_key_exchange: the message to print
 */
void print_client_key_exchange(client_key_exchange_t *client_key_exchange){
    printf(" Public key: ");
    for(int i = 0; i<client_key_exchange->key_length; i++)
        printf("%02X ",client_key_exchange->key[i]);
    printf("\n");
}

/**
 * Dealloc memory of client key exchange.
 *
 *	\param client_key_exchange: the client key exchange message to deallocate
 */
void free_client_key_exchange(client_key_exchange_t *client_key_exchange){
    free(client_key_exchange->key);
    free(client_key_exchange);
}
