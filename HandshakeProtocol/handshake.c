

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