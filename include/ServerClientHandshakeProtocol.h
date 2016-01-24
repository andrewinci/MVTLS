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

#include "ServerClientRecordProtocol.h"
#include "handshakeConstants.h"

#ifdef MAKEFILE
#include "HandshakeMessages/ServerClientHello.h"
#include "HandshakeMessages/Certificate.h"
#include "HandshakeMessages/ServerClientKeyExchange.h"
#else
#include "ServerClientHello.h"
#include "Certificate.h"
#include "ServerClientKeyExchange.h"
#endif

#endif

// Header
typedef struct{
	uint8_t type;
	uint32_t length;  
    unsigned char *message;
} handshake;


int send_handshake(channel *ch, handshake *h);

void serialize_handshake(handshake *h, unsigned char **stream, uint32_t *streamLen);

handshake *deserialize_handshake(unsigned char *message, uint32_t messageLen);

void print_handshake(handshake *h);

void free_handshake(handshake *h);