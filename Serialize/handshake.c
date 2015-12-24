/*
First test of structure of an handshake
*/

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

// 32-bit of random
typedef struct random_t {
	uint32_t UNIX_time;
	uint8_t random_bytes[28];
} random;

// Session ID
typedef struct session_id_t {
	uint8_t session_lenght;
	uint8_t *session_id;
} session_id;

// Ciphers suite list
typedef struct cipher_suites_t {
	uint8_t length;
	uint16_t *cipher_id;

} cipher_suites;

// (Useless) Compression methods
typedef struct compression_methods_t {
	uint16_t length;
	uint8_t compression_id;
} compression_methods;

// Header
typedef struct handshake_header_t {
	uint8_t type;
	uint32_t length;
	uint16_t TLS_version;
} handshake_header;

// Handshake packet
typedef struct handshake_t {
	handshake_header header;				// 7 bytes
	random random;							// 32 bytes
	session_id session_id;					// 1+session_id.session_lenght bytes
	cipher_suites cipher_suites;			// 1+2*cipher_suites.lenght bytes
	compression_methods compression_methods;// 3 bytes
} handshake;

handshake new_handshake(handshake a) {
	a.header.type = 0x01;
	a.header.TLS_version = 0x0301;
	a.random.UNIX_time = (uint32_t)time(NULL);
	for(int i=0; i<28; i++){
		a.random.random_bytes[i] = i;
	}
	a.session_id.session_lenght = 0x02;
	a.session_id.session_id = (uint8_t *)malloc(sizeof(uint8_t)*a.session_id.session_lenght);
	for(int i=0; i<(int)a.session_id.session_lenght; i++){
		*(a.session_id.session_id+i) = 0x01;
	}
	a.cipher_suites.length = 0x02;
	a.cipher_suites.cipher_id = (uint16_t *)malloc(sizeof(uint16_t)*a.session_id.session_lenght);
	for(int i=0; i<(int)a.cipher_suites.length; i++) {
		*(a.cipher_suites.cipher_id+2*i) = 0x0002;
	}
	a.compression_methods.length = 0x01;
	a.compression_methods.compression_id = 0x00;

	// Computing lengths
	a.header.length = 39+a.session_id.session_lenght+2*a.cipher_suites.length;

	return(a);
}

int serialize_header(unsigned char *buf, handshake_header h){
	
	unsigned char *ptr;

	ptr = buf;
	memcpy(ptr, &(h.type), sizeof(uint8_t));
	ptr += sizeof(uint8_t);
	memcpy(ptr, &(h.length), sizeof(uint32_t));
	ptr += sizeof(uint32_t);
	memcpy(ptr, &(h.TLS_version), sizeof(uint16_t));
	ptr += sizeof(uint16_t);

	return(ptr-buf);
}

int serialize_random(unsigned char *buf, random r){

	unsigned char *ptr;

	ptr = buf;
	memcpy(ptr, &(r.UNIX_time), sizeof(uint32_t));
	ptr += sizeof(uint32_t);
	for(int i=0; i<28; i++) {
		memcpy(ptr+i, &(r.random_bytes[i]), sizeof(uint8_t));
	}

	return(ptr+28-buf);
}

int serialize_session_id(unsigned char *buf, session_id s){

	unsigned char *ptr;

	ptr = buf;
	memcpy(ptr, &(s.session_lenght), sizeof(uint8_t));
	ptr += sizeof(uint8_t);
	for(int i=0; i<s.session_lenght; i++) {
		memcpy(ptr, s.session_id+i, sizeof(uint8_t));
		ptr += sizeof(uint8_t);
	}

	return(ptr-buf);
}

int serialize_cipher_suites(unsigned char *buf, cipher_suites c){

	unsigned char *ptr;

	ptr = buf;
	memcpy(ptr, &(c.length), sizeof(uint8_t));
	ptr += sizeof(uint8_t);
	for(int i=0; i<c.length; i++) {
		memcpy(ptr, c.cipher_id+2*i, sizeof(uint16_t));
		ptr += sizeof(uint16_t);
	}

	return(ptr-buf);
}

int serialize_compression_methods(unsigned char *buf, compression_methods c){

	unsigned char *ptr;

	ptr = buf;
	memcpy(ptr, &(c.length), sizeof(uint16_t));
	ptr += sizeof(uint16_t);
	memcpy(ptr, &(c.compression_id), sizeof(uint8_t));
	ptr += sizeof(uint8_t);

	return(ptr-buf);
}

unsigned char *serialize_handshake(handshake a){

	unsigned char *buf;
	int mov=0;
	buf = (char *)malloc(sizeof(char)*(a.header.length+5));	// +1 byte type, +3 (4) byte length
	
	mov += serialize_header(buf+mov, a.header);
	mov += serialize_random(buf+mov, a.random);
	mov += serialize_session_id(buf+mov, a.session_id);
	mov += serialize_cipher_suites(buf+mov, a.cipher_suites);
	mov += serialize_compression_methods(buf+mov, a.compression_methods);

	return(buf);
}

int main() {

	handshake a;
	unsigned char *test;

	a = new_handshake(a);
	test = serialize_handshake(a);
	printf("Serialized handshake:\n");
	printf("Type: %02X\n", *test);
	printf("Length: %02X%02X%02X\n", *(test+3), *(test+2), *(test+1));
	printf("TLS version: %01X.%01X\n", *(test+6), *(test+5));
	printf("UNIX time: %02X%02X%02X%02X\n", *(test+10), *(test+9), *(test+8), *(test+7));
	printf("Random bytes: ");
	for (int i=0; i<28; i++) {
		printf("%02X", *(test+11+i));
	}
	printf("\n");
	printf("Session length: %02X\n", *(test+39));
	printf("Session ID: ");
	for(int i=0; i<a.session_id.session_lenght; i++){
		printf("%02X", *(test+40+i));
	}
	printf("\n");
	printf("Cipher suites length: %02X\n", *(test+40+a.session_id.session_lenght));
	printf("Cipher IDs: \n");
	for(int i=0; i<a.cipher_suites.length; i++){
		printf("%02X%02X\n", *(test+41+a.session_id.session_lenght+2*i+1), *(test+41+a.session_id.session_lenght+2*i));
	}
	printf("Compression methods length: %02X\n", *(test+41+a.session_id.session_lenght+2*a.cipher_suites.length));
	printf("Compression method: %02X\n", *(test+42+a.session_id.session_lenght+2*a.cipher_suites.length));

	return(0);
}