//
//  ServerClientFileSocket.h
//  SSLTLSFile
//
//  Created by Darka on 16/12/15.
//  Copyright © 2015 Darka. All rights reserved.
//
//  Basic client server comunication through file
//
//  PROTOCOL:
//  The protocol is very basic
//  1° line : the message
//  last line -1: from
//  last line : to
//  The order is usefull for understand if the other side have finished
//
//  both server and client after read a message they blank the file
//
//

#ifndef ServerClientFileSocket_h
#define ServerClientFileSocket_h

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>

#endif /* ServerClientFileSocket_h */

// operation mode (not pratically use)
enum mode{
    SERVER,CLIENT
};

// basic packet
typedef struct packet{
    char *from;
    char *to;
    char *message;
    uint32_t messageLen;
}packet;

typedef struct channel{
    // server client mode
    enum mode mod;
    // channel name
    char *channelName;
    // file to use for exchange messages
    char *fileName;
    // file descriptor
    FILE *file;
    // function to be called when a packet is received
    void (*onPacketReceive)(struct channel *ch, packet *p);
    // value to establish if reading thread is enabled
    int isEnabled;
    // reading thread
    pthread_t thread;
}channel;


/*
 * Create a server/clinet using the fileName as comunication channel
 * fileName : file name of the channel
 * serverName : name of the server/client
 */
channel *createChannel(char *fileName,char *channelName, enum mode channelMode);

/*
 * Set the function to be called when a message is received
 * ch : channel interested
 * onPacketReceive : pointer to the function
 * return : 1 if the function was setted, 0 otherwise
 */
int setOnReceive(channel *ch, void (*onPacketReceive)(channel *ch, packet *p));

/*
 * Send a message trough the channel ch
 * ch : channel to be used
 * p : pointer to packet to be sent
 * return : 1 if the message was sent, 0 otherwise
 */
int sendPacket(channel *ch, packet *p);

/*
 * Start the channel. We open another thread for the reading
 * and the current thread for writing. From now on (if the operation
 * is succesfull) the clinet/server read continously from chanell.
 * (for STOP use stop())
 * return : 1 if the thread was started, 0 otherwise
 */
int startChannel(channel *ch);

/*
 * Stop the main and wait untill stop is called
 */
void waitChannel(channel *ch);

/*
 * Stop the reading thread and the channel
 * Doesn't free the channel, this operation 
 * has to be done manually with free()
 */
void stopChannel(channel *ch);

packet *createPacket(char *from, char *to, char *message, uint32_t messageLen);

void freePacket(packet *p);