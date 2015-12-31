//
//  SSL/TLS Project
//  ServerClientFileSocket.h
//
//  Created on 22/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//
//  Basic client server comunication through file
//
//  PROTOCOL:
//  The protocol is very basic
//  8 byte for source
//  8 byte for receiver
//  4 byte for packet length
//  message
//  
//
//  both server and client after read a message they blank the file
//  both server and client cannot write if the file is not blank, they wait
//

#ifndef ServerClientBasic_h
#define ServerClientBasic_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>

#endif

#define DELAY_TIME 100

// operation mode
#ifndef enum_mode
#define enum_mode
typedef enum{
    SERVER,CLIENT
}mode;
#endif

#ifndef struct_packet
#define struct_packet
// basic packet
typedef struct{
    char *source; //8 byte
    char *destination;   //8 byte
    uint32_t messageLen;
    unsigned char *message;

}packet_basic;
#endif

#ifndef struct_channel
#define struct_channel
typedef struct channel{
    // server client mode
    mode mod;
    // channel from
    char *channel_source;
    // channel to
    char *channel_destination;
    // file to use for exchange messages
    char *fileName;
    // file descriptor
    FILE *file;
    // function to be called when a packet is received
    void (*onPacketReceive)(struct channel *ch, packet_basic *p);
    // value to establish if reading thread is enabled
    int isEnabled;
    // reading thread
    pthread_t thread;
}channel;
#endif

/*
 * Create a server/client using the fileName as comunication channel
 *
 * fileName : file name of the channel
 * serverName : name of the server/client
 * return the created channel
 */
channel *create_channel(char *fileName, char *channelFrom, char *channelTo, mode channelMode);

/*
 * Set the function to be called when a message is received
 *
 * ch : channel interested
 * onPacketReceive : pointer to the function
 * return : 1 if the function was setted, 0 otherwise
 */
int set_on_receive(channel *ch, void (*onPacketReceive)(channel *ch, packet_basic *p));

/*
 * Send a message trough the channel ch
 *
 * ch : channel to be used
 * p : pointer to packet to be sent
 * return : 1 if the message was sent, 0 otherwise
 */
int send_packet(channel *ch, packet_basic *p);

/*
 * Start the channel. We open another thread for the reading
 * and the current thread for writing. From now on (if the operation
 * is succesfull) the client/server read continously from channel.
 * (for STOP use stop())
 *
 * ch : channel to start
 * return : 1 if the thread was started, 0 otherwise
 */
int start_channel(channel *ch);

/*
 * Stop the main and wait untill stop is called
 */
void wait_channel(channel *ch);

/*
 * Stop the reading thread and the channel
 * It doesn't free the channel, this operation
 * has to be done manually with free()
 */
void stop_channel(channel *ch);

/*
 * Create a packet
 *
 * from : packet source
 * to   : packet receiver
 * message : the message to be sent
 * messageLen : message lenght (only message)
 */
packet_basic *create_packet(char *from, char *to, unsigned char *message, uint32_t messageLen);

/*
 * Delete and free memory allocated by packet
 *
 * p : packet to remove
 */
void free_packet(packet_basic *p);
