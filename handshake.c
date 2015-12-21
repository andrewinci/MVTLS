/*
First test of structure of an handshake
*/

#include <stdio.h>
#include <stdint.h>

// 3-byte new type
typedef uint32_t uint24_t;

// Record
typedef struct record_t {
	uint8_t record_type;
	uint16_t TLS_version, length;
} record;

// 32-bit of random
typedef struct random_t {
	uint32_t UNIX_time;
	uint8_t random_bytes[28];
} random;

// Session ID
typedef struct session_id_t {
	uint8_t session_lenght;
	uint32_t session_id;
} session_id;

// Ciphers suite list
typedef struct cipher_suites_t
{
	uint8_t length, cipher_id[2];

} cipher_suites;

// (Useless) Compression methods
typedef struct compression_methods_t {
	uint16_t length;
	uint8_t compression_id;
} compression_methods;

// Handshake packet
typedef struct handshake_t {
	record record;
	uint8_t type;
	uint24_t length;
	uint16_t TLS_version;
	random random;
	session_id session_id;
	cipher_suites cipher_suites;
	compression_methods compression_methods;
} handshake;

int main() {

	// Test
	handshake a;
	a.record.record_type = 0x16;
	a.record.TLS_version = 0x0303;
	a.record.length = 2;
	a.type = 0x01;
	a.length = 3;
	a.TLS_version = 0x0303;
	a.random.UNIX_time = 123;
	for(int i=0; i<28; i++){
		a.random.random_bytes[i] = i;
	}
	a.session_id.session_lenght = 1;
	a.session_id.session_id = 1;
	a.cipher_suites.length = 2;
	a.cipher_suites.cipher_id[0] = 0x00;
	a.cipher_suites.cipher_id[1] = 0x00;
	a.compression_methods.length = 1;
	a.compression_methods.compression_id = 0x00;

	return(0);
}