//
//  SSL/TLS Project
//  ServerClientFileSocket.c
//
//  Created on 22/12/15.
//  Copyright © 2015 Mello, Darka. All rights reserved.
//

#include "ServerClientBasic.h"


void free_packet(packet *p);
uint32_t read_all_file(FILE *f, unsigned char **p);
packet *deserialize_packet(unsigned char *str, uint32_t fileLen);
void serialize_packet(packet *p, unsigned char **str, uint32_t *strLen);


channel *create_channel(char *fileName, char *channelFrom, char *channelTo, mode channelMode){
    channel *ch = malloc(sizeof(channel));
    ch->mod = channelMode;
    ch->channelFrom = channelFrom;
    ch->channelTo = channelTo;
    if(channelMode == SERVER)
        ch->file = fopen(fileName, "w+");
    else ch->file = fopen(fileName, "a+");
    ch->fileName = fileName;
    ch->onPacketReceive = NULL;
    ch->isEnabled = 0;
    return ch;
}

int set_on_receive(channel *ch, void (*onPacketReceive)(channel *ch, packet *p)){
    if(ch->onPacketReceive == NULL){
        //check if the packet is for the channel owner
        ch->onPacketReceive = onPacketReceive; //channel and struct channel_t are the same TODO: cast
        return 1;
    }
    return 0;
}

int send_packet(channel *ch, packet *p){
    if(ch->file==NULL)
        return 0;
    
    unsigned char *message = NULL;
    uint32_t strLen;

    if(p->from == NULL){
        p->from = calloc(8,1);
        memcpy(p->from, ch->channelFrom, strlen(ch->channelFrom));
    }
    
    if(p->to == NULL){
        p->to = calloc(8,1);
        memcpy(p->to, ch->channelTo, strlen(ch->channelTo));
    }
    
    serialize_packet(p, &message, &strLen);
    if(message == NULL)
        return 0;
    //printf("Packet to send:\n%.*s\n",strLen,message);
    unsigned long writeResult = fwrite(message, 1, strLen, ch->file);
    //free(message);
    if(writeResult)
        return 1;
    return 0;
}

void reader(void *data){
    channel *ch;
    ch = (channel*)data;
    while (ch->isEnabled) {
        unsigned char *str = NULL;
        uint32_t fileLen = read_all_file(ch->file, &str);
        if(fileLen>3){
            //the file is not empty
            packet *received = deserialize_packet(str, fileLen);
            if(received!=NULL && strcmp(received->to, ch->channelFrom)==0){
                //blank the file
                fclose(ch->file);
                ch->file = fopen(ch->fileName, "w+");
                ch->onPacketReceive(ch,received);
            }  else free_packet(received);
        }
        free(str);
        usleep(DELAY_TIME);
    }
}

int start_channel(channel *ch){
    if(ch->onPacketReceive==NULL)
        return 0;
    
    pthread_t thread;
    pthread_attr_t attr ;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ch->isEnabled = 1;
    int rc = pthread_create(&thread, &attr, (void *)&reader, (void *)ch);
    if (rc){
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        exit(-1);
    }
    ch->thread = thread;
    return 1;
}

void stop_channel(channel *ch){
    ch->isEnabled = 0;
    pthread_exit(NULL);
}

void wait_channel(channel *ch){
    pthread_join(ch->thread, NULL);
}

packet *create_packet(char *from, char *to, unsigned char *message, uint32_t messageLen){
    packet *result = malloc(sizeof(packet));
    
    result->from = NULL;
    result->to = NULL;
    result->message = NULL;
    
    if(from!=NULL){
        result->from = calloc(8,1);
        memcpy(result->from, from, strlen(from));
    }
    if(to!=NULL){
        result->to = calloc(8,1);
        memcpy(result->to, to, strlen(to));
    }
    if(message!=NULL){
        result->message = malloc(messageLen);
        memcpy(result->message, message, messageLen);
    }
    result->messageLen = messageLen;
    return result;
}

void free_packet(packet *p){
    if(p==NULL)
        return;
    if(p->from!=NULL)
        free(p->from);
    if(p->to!=NULL)
        free(p->to);
    if(p->message!=NULL)
        free(p->message);
    free(p);
}

/********* Utility function for file managing *********/

/*
 * Compute the byte size of a file
 * f : file indentificator
 * return : the lenght of the file in byte
 */
long get_file_size(FILE *f){
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f,0,SEEK_SET);
    return fsize;
}

/*
 * Reading the entire file
 * f : file identificator
 * p : return pointer
 * return : the file size
 */
uint32_t read_all_file(FILE *f, unsigned char **p){
    long fileSize = get_file_size(f);
    if(fileSize>UINT32_MAX)
    {
        printf("\nThe message is too long, something went wrong\n");
        exit(-1);
    }
    unsigned char *temp=malloc(fileSize*sizeof(unsigned char));
    fread(temp,fileSize,1,f);
    //printf("\n%.*s\n",fileSize,temp);
    *p=temp;
    return (uint32_t)fileSize;
}


/********* Serialization deserialization *********/

/*
 * Parse the message into packet
 * str : string received
 * fileLen : received string length
 */
packet *deserialize_packet(unsigned char *str, uint32_t fileLen){
    
    char *from = calloc(8, 1);
    char *to = calloc(8, 1);
    uint32_t packLen;
    unsigned char *message;
    
    memcpy(from, str, 8);
    memcpy(to, str+8, 8);
    memcpy(&packLen, str+16, 4);
    message = str+20;
    
    if(packLen!=fileLen){//the packet is malformed
        free(from);
        free(to);
        return NULL;
    }
    
    packet *result = create_packet(from, to, message, packLen-20);
    free(from);
    free(to);
    return result;
}

/*
 * Serialize the packet into a byte stream
 * p : pacjet to serialize
 * str : pointer to a null string (used for return the stream)
 * strlen : pointer to stream length (used for return the stream length)
 */
void serialize_packet(packet *p, unsigned char **str, uint32_t *strLen){
    if(p->from == NULL || p->to == NULL || p->message == NULL)
    {
        *str = NULL;
        *strLen = 0;
        return;
    }
    *strLen = p->messageLen+4+8+8;
    *str = malloc(*strLen);

    if(*str!=NULL){
        memcpy(*str, p->from, 8);
        memcpy(*str+8, p->to, 8);
        memcpy(*str+16, strLen, 4);
        memcpy(*str+20,p->message,p->messageLen);
    }else
    {
        printf("\nMalloc fail in serialize\n");
        exit(-1);
    }
}





