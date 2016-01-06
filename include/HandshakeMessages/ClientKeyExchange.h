//
//  SSL/TLS Project
//  ClientKeyExchange.h
//
//  Created on 06/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#ifndef ClientKeyExchange_h
#define ClientKeyExchange_h
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REV32(value)({(value & 0x000000FFU) << 24 | (value & 0x0000FF00U) << 8 |(value & 0x00FF0000U) >> 8 | (value & 0xFF000000U) >> 24;})
#endif

#ifdef MAKEFILE
#include "../handshakeConstants.h"
#else
#include "handshakeConstants.h"
#endif

void serialize_key_exchange(uint32_t key_length, unsigned char *encrypted_premaster_key, unsigned char **stream, uint32_t *len, key_exchange_algorithm kx);

void deserialize_key_exchange(uint32_t message_len, unsigned char *message, unsigned char **encrypted_premaster_key, uint32_t *key_len, key_exchange_algorithm kx);