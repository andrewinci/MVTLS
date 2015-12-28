//
//  SSL/TLS Project
//  ServerClientHandshakeProtocol.h
//
//  Created on 27/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
//  This file is used to mange the handshake protocol
//
#ifndef ServerClientHandshakeProtocol_h

#define ServerClientHandshakeProtocol_h

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "../RecordProtocol/ServerClientRecordProtocol.h"
#include "ServerClientHello.h"

#define DEFAULT_TLS_VERSION 0x0303
#endif

/*
 * Types of handshake packet
 */
enum {
    HELLO_REQUEST           = 0x00,
    CLIENT_HELLO            = 0x01,
    SERVER_HELLO            = 0x02,
    CERTIFICATE             = 0x0B,
    SERVER_KEY_EXCHANGE     = 0x0C,
    CERTIFICATE_REQUEST     = 0x0D,
    SERVER_DONE             = 0x0E,
    CERTIFICATE_VERIFY      = 0x0F,
    CLIENT_KEY_EXCHANGE     = 0x10,
    FINISHED                = 0x14
};

// Header
typedef struct{
	uint8_t type;
	uint32_t length;
	uint16_t TLS_version;
    unsigned char *message;
} handshake;


int send_handshake(channel *ch, handshake *h);

void serialize_handshake(handshake *h, unsigned char **stream, uint32_t *streamLen);

handshake *deserialize_handshake(unsigned char *message, uint32_t messageLen);

void print_handshake(handshake *h);