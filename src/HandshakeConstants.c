/**
 *	SSL/TLS Project
 *	\file HandshakeConstants.c
 *
 * 	This file contains a set of constants used in 
 * 	the handshake protocol and function implementation 
 *	to manage the supported cipher suite.
 *
 *	\date Created on 24/12/15.
 *	\copyright Copyright © 2015 Alessandro Melloni, Andrea Francesco Vinci. All rights reserved.
 *
 */

#include "HandshakeConstants.h"
/** The number of supported cipher suites */
const int NUM_CIPHER_SUITE = 62;

/** List of supported cipher suites */
cipher_suite_t cipher_suite_list[] ={
	// RSA
	{0x0001 , "TLS_RSA_WITH_NULL_MD5" , 1 , 1 , 0 , 1 },
	{0x0002 , "TLS_RSA_WITH_NULL_SHA" , 1 , 1 , 0 , 2 },
	{0x0004 , "TLS_RSA_WITH_RC4_128_MD5" , 1 , 1 , 128 , 1 },
	{0x0005 , "TLS_RSA_WITH_RC4_128_SHA" , 1 , 1 , 128 , 2 },
	{0x0007 , "TLS_RSA_WITH_IDEA_CBC_SHA" , 1 , 1 , 128 , 2 },
	{0x0009 , "TLS_RSA_WITH_DES_CBC_SHA" , 1 , 1 , 56 , 2 },
	{0x000A , "TLS_RSA_WITH_3DES_EDE_CBC_SHA" , 1 , 1 , 168 , 2 },
	{0x002F , "TLS_RSA_WITH_AES_128_CBC_SHA" , 1 , 1 , 128 , 2 },
	{0x0035 , "TLS_RSA_WITH_AES_256_CBC_SHA" , 1 , 1 , 256 , 2 },
	{0x003B , "TLS_RSA_WITH_NULL_SHA256" , 1 , 1 , 0 , 4 },
	{0x003C , "TLS_RSA_WITH_AES_128_CBC_SHA256" , 1 , 1 , 128 , 4 },
	{0x003D , "TLS_RSA_WITH_AES_256_CBC_SHA256" , 1 , 1 , 256 , 4 },
	{0x0041 , "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" , 1 , 1 , 128 , 2 },
	{0x0084 , "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" , 1 , 1 , 256 , 2 },
	{0x0096 , "TLS_RSA_WITH_SEED_CBC_SHA" , 1 , 1 , 128 , 2 },
	{0x009C , "TLS_RSA_WITH_AES_128_GCM_SHA256" , 1 , 1 , 128 , 4 },
	{0x009D , "TLS_RSA_WITH_AES_256_GCM_SHA384" , 1 , 1 , 256 , 5 },

	// ECDHE
	{0xC006 , "TLS_ECDHE_ECDSA_WITH_NULL_SHA" , 3 , 3 , 0 , 2 },
	{0xC007 , "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" , 3 , 3 , 128 , 2 },
	{0xC008 , "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" , 3 , 3 , 168 , 2 },
	{0xC009 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" , 3 , 3 , 128 , 2 },
	{0xC00A , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" , 3 , 3 , 256 , 2 },
	{0xC023 , "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" , 3 , 3 , 128 , 4 },
	{0xC024 , "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" , 3 , 3 , 256 , 5 },
	{0xC02B , "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" , 3 , 3 , 128 , 4 },
	{0xC02C , "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" , 3 , 3 , 256 , 5 },
	{0xC010 , "TLS_ECDHE_RSA_WITH_NULL_SHA" , 3 , 1 , 0 , 2 },
	{0xC011 , "TLS_ECDHE_RSA_WITH_RC4_128_SHA" , 3 , 1 , 128 , 2 },
	{0xC012 , "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" , 3 , 1 , 168 , 2 },
	{0xC013 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" , 3 , 1 , 128 , 2 },
	{0xC014 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" , 3 , 1 , 256 , 2 },
	{0xC027 , "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" , 3 , 1 , 128 , 4 },
	{0xC028 , "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" , 3 , 1 , 256 , 5 },
	{0xC02F , "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" , 3 , 1 , 128 , 4 },
	{0xC030 , "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" , 3 , 1 , 256 , 5 },

	// DHE
	{0x0011 , "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" , 2 , 2 , 40 , 2 },
	{0x0012 , "TLS_DHE_DSS_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
	{0x0013 , "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" , 2 , 2 , 168 , 2 },
	{0x0032 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" , 2 , 2 , 128 , 2 },
	{0x0038 , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" , 2 , 2 , 256 , 2 },
	{0x0040 , "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" , 2 , 2 , 128 , 4 },
	{0x0044 , "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" , 2 , 2 , 128 , 2 },
	{0x0063 , "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" , 2 , 2 , 56 , 2 },
	{0x0065 , "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" , 2 , 2 , 56 , 2 },
	{0x0066 , "TLS_DHE_DSS_WITH_RC4_128_SHA" , 2 , 2 , 128 , 2 },
	{0x006A , "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" , 2 , 2 , 256 , 4 },
	{0x0087 , "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" , 2 , 2 , 256 , 2 },
	{0x0099 , "TLS_DHE_DSS_WITH_SEED_CBC_SHA" , 2 , 2 , 128 , 2 },
	{0x00A2 , "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" , 2 , 2 , 128 , 4 },
	{0x00A3 , "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" , 2 , 2 , 256 , 5 },
	{0x0014 , "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" , 2 , 1 , 40 , 2 },
	{0x0015 , "TLS_DHE_RSA_WITH_DES_CBC_SHA" , 2 , 1 , 56 , 2 },
	{0x0016 , "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" , 2 , 1 , 168 , 2 },
	{0x0033 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" , 2 , 1 , 128 , 2 },
	{0x0039 , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" , 2 , 1 , 256 , 2 },
	{0x0045 , "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" , 2 , 1 , 128 , 2 },
	{0x0067 , "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" , 2 , 1 , 128 , 4 },
	{0x006B , "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" , 2 , 1 , 256 , 4 },
	{0x0088 , "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" , 2 , 1 , 256 , 2 },
	{0x009A , "TLS_DHE_RSA_WITH_SEED_CBC_SHA" , 2 , 1 , 128 , 2 },
	{0x009E , "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" , 2 , 1 , 128 , 4 },
	{0x009F , "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" , 2 , 1 , 256 , 5 },
	{0x0000 , NULL, -1, -1, -1, -1}
};

/**
 * Get the hash algorithm starting from the hash id.
 *
 *	\param h: the hash algorithm used
 *	\return an EVP_MD struct used to compute digest
 */
const EVP_MD *get_hash_function(hash_algorithm h){
	switch (h) {
		case SHA1_H:
			return EVP_sha();

		case SHA224_H:
			return EVP_sha224();

		case SHA256_H:
			return EVP_sha256();

		case SHA384_H:
			return EVP_sha384();

		case SHA512_H:
			return EVP_sha512();

		case MD5_H:
			return EVP_md5();

		default:
			return NULL;
	}
}

/**
 * Fill array[] with all cipher suites that has key exchange kx, 
 * hash algorithm h and authentication algorithm au.
 * 
 *
 *	\param kx: the key exchange algorithm (if NONE_KX the function consider all key exchange algorithms)
 *	\param h: the hash algorithm (if NONE_H the function consider all hash algorithms)
 * 	\param au: the authentication algorithm (if NONE_AU the function consider all authentication algorithms)
 *	\param array[]: an empty array of size NUM_CIPHER_SUITE.
 *	\return the number of cipher suites loaded in array[]
 */
int get_cipher_suites(key_exchange_algorithm kx, hash_algorithm h, authentication_algorithm au, cipher_suite_t array[]){
	int j = 0;
	for(int i=0;i<NUM_CIPHER_SUITE;i++)
		if( (kx == NONE_KX || cipher_suite_list[i].kx == kx) && (h == NONE_H || cipher_suite_list[i].hash == h) && (au == NONE_AU || cipher_suite_list[i].au == au)){
			array[j] = cipher_suite_list[i];
			j++;
		}

	return j;
}

/**
 * Given the cipher suite name return the cipher suite struct.
 *
 *	\param name: cipher suite name
 *	\return cipher suite struct with name name
*/
cipher_suite_t get_cipher_suite_by_name(char *name){
	int i=0;
	for(; i<NUM_CIPHER_SUITE && strcmp(cipher_suite_list[i].name, name) != 0; i++);

	return cipher_suite_list[i];
}

/**
 * Given the id of a cipher suite return the cipher suite struct.
 *
 *	\param id: cipher suite id
 *	\return cipher suite struct with id id
 */
cipher_suite_t get_cipher_suite_by_id(uint16_t id){
	int i=0;
	for(;i<NUM_CIPHER_SUITE && cipher_suite_list[i].cipher_id != id;i++);

	return cipher_suite_list[i];
}
