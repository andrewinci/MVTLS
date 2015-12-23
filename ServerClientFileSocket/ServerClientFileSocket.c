//
//  ServerClientFileSocket.c
//  SSLTLSFile
//
//  Created by Darka on 16/12/15.
//  Copyright © 2015 Darka. All rights reserved.
//

#include "ServerClientFileSocket.h"

uint32_t readAllFille(FILE *f, char **p);
packet *deserializePacket(char *str, uint32_t fileLen);
void serializePacket(packet *p, char **str, uint32_t *strLen);
void freePacket(packet *p);

channel *createChannel(char *fileName, char *channelName, enum mode channelMode){
    channel *ch = malloc(sizeof(channel));
    ch->mod = channelMode;
    ch->channelName = channelName;
    if(channelMode == SERVER)
        ch->file = fopen(fileName, "w+");
    else ch->file = fopen(fileName, "a+");
    ch->fileName = fileName;
    ch->onPacketReceive = NULL;
    ch->isEnabled = 0;
    return ch;
}

int setOnReceive(channel *ch, void (*onPacketReceive)(channel *ch, packet *p)){
    if(ch->onPacketReceive == NULL){
        //check if the packet is for the channel owner
        ch->onPacketReceive = onPacketReceive; //channel and struct channel_t are the same TODO: cast
        return 1;
    }
    return 0;
}


int sendPacket(channel *ch, packet *p){
    if(ch->file==NULL || p->to == NULL)
        return 0;
    char *message = NULL;
    uint32_t strLen;
    if(p->from == NULL){
        p->from = malloc(strlen(ch->channelName));
        memccpy(p->from, ch->channelName, 1, strlen(ch->channelName));
    }
    serializePacket(p, &message, &strLen);
    if(message == NULL)
        return 0;
    printf("Packet to send:\n%.*s\n",strLen,message);
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
        char *str = NULL;
        uint32_t fileLen = readAllFille(ch->file, &str);
        if(fileLen>3){
            //the file is not empty
            packet *received = deserializePacket(str, fileLen);
            if(received!=NULL && strcmp(received->to, ch->channelName)==0){
                //blank the file
                fclose(ch->file);
                ch->file = fopen(ch->fileName, "w+");
                ch->onPacketReceive(ch,received);
            }  else freePacket(received);
        }
        free(str);
        usleep(500);
    }
}

int startChannel(channel *ch){
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

void stopChannel(channel *ch){
    ch->isEnabled = 0;
    pthread_exit(NULL);
}

void waitChannel(channel *ch){
    pthread_join(ch->thread, NULL);
}

/********* Utility function *********/

/*
 * Compute the byte size of a file
 * f : file indentificator
 * return : the lenght of the file in byte
 */
long getFileSize(FILE *f){
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
uint32_t readAllFille(FILE *f, char **p){
    long fileSize = getFileSize(f);
    if(fileSize>UINT32_MAX)
    {
        printf("\nThe message is too long, something went wrong\n");
        exit(-1);
    }
    char *temp=malloc(fileSize*sizeof(char));
    fread(temp,fileSize,1,f);
    //printf("\n%.*s\n",fileSize,temp);
    *p=temp;
    return (uint32_t)fileSize;
}


/*
 * Parse the message into packet
 * str : string received
 * fileLen : received string length
 */
packet *deserializePacket(char *str, uint32_t fileLen){
    
    char *strStart = str;
    char *strEnd = strStart+fileLen;
    char **temp = malloc(3*sizeof(char*));
    int count = 0;
    
    while (strEnd>strStart && count<2) {
        while (strEnd>strStart && *strEnd!='\n')
            strEnd--;
        *strEnd = '\0';
        temp[count] = ++strEnd;
        count++;
    }

    if(count != 2)
        return NULL;

    long messageLen = fileLen-strlen(temp[0])-strlen(temp[1])-2;
    
    if(messageLen<0)
        return NULL;
    packet *result = createPacket(temp[1], temp[0], strStart, (uint32_t)messageLen);
    free(temp);
    return result;
}

void serializePacket(packet *p, char **str, uint32_t *strLen){
    if(p->from == NULL || p->to == NULL || p->message == NULL)
    {
        *str = NULL;
        *strLen = 0;
        return;
    }
    *strLen = p->messageLen+(uint32_t)strlen(p->from)+(uint32_t)strlen(p->to)+2;
    *str = malloc(*strLen+1);
    if(*str!=NULL){
//        memccpy(*str, p->from, 1, strlen(p->from)+1);
//        strncat(*str,"\n", 1);
//        strncat(*str, p->to, strlen(p->to));
//        strncat(*str,"\n", 1);
//        strncat(*str,p->message,p->messageLen);
        
        memcpy(*str,p->message,p->messageLen);
        strncat(*str,"\n", 1);
        strncat(*str, p->from, strlen(p->from));
        strncat(*str,"\n", 1);
        strncat(*str, p->to, strlen(p->to));
        
        
    }else
    {
        printf("\nMalloc fail in serialize\n");
        exit(-1);
    }
}

packet *createPacket(char *from, char *to, char *message, uint32_t messageLen){
    packet *result = malloc(sizeof(packet));
    
    result->from = NULL;
    result->to = NULL;
    result->message = NULL;
    
    if(from!=NULL){
        result->from = malloc(strlen(from));
        memcpy(result->from, from, strlen(from));
    }
    if(to!=NULL){
        result->to = malloc(strlen(to));
        memcpy(result->to, to, strlen(to));
    }
    if(message!=NULL){
        result->message = malloc(messageLen);
        memcpy(result->message, message, messageLen);
    }
    result->messageLen = messageLen;
    return result;
}

void freePacket(packet *p){
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



