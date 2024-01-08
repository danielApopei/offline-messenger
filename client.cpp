#include "structures.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 2024
#define MAX_WORDS 32

void* receiveThread(void* arg) {
    int clientSocket = *(int*)arg;
    while (1) {
        unsigned char receivedBuffer[sizeof(Packet)];
        ssize_t totalBytesReceived = 0;
        ssize_t bytesReceived;
        while (totalBytesReceived < sizeof(Packet)) {
            bytesReceived = recv(clientSocket, receivedBuffer + totalBytesReceived, sizeof(receivedBuffer) - totalBytesReceived, 0);
            if (bytesReceived <= 0) {
                break;
            }
            totalBytesReceived += bytesReceived;
        }
        Packet receivedPacket;
        deserializePacket(receivedBuffer, &receivedPacket);
        decode_vigenere_packet(&receivedPacket, vigenere_key);
        printf("type: %d; error: %d\n", receivedPacket.type, receivedPacket.error);
        if (totalBytesReceived > 0) {
            switch(receivedPacket.type) {
                case REGISTER_RESPONSE: {
                    if(receivedPacket.error == USER_ALREADY_EXISTS)
                        printf("\n-- That username is already taken!\n");
                    else
                        printf("\n-- Welcome, %s!\n", receivedPacket.user.username);
                    fflush(stdout);
                    break;
                }
                case LOGIN_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_OUT)
                        printf("\n-- You are already logged in!\n");
                    else if(receivedPacket.error == INVALID_USER_DATA)
                        printf("\n-- Username or password wrong!\n");
                    else if(receivedPacket.error == USER_ALREADY_CONNECTED)
                        printf("\n-- User is already connected on different device!\n");
                    else
                        printf("\n-- Welcome, %s!\n", receivedPacket.user.username);
                    fflush(stdout);
                    break;
                }
                case LOGOUT_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("\n-- You are not logged in!\n");
                    else
                        printf("\n-- Goodbye, %s!\n", receivedPacket.user.username);
                    fflush(stdout);
                    break;
                }
                case SEND_MESSAGE_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("\n-- You are not logged in!\n");
                    else if(receivedPacket.error == INVALID_USER_DATA)
                        printf("\n-- No such user!\n");
                    else if(receivedPacket.error == INVALID_REPLY_ID)
                    printf("\n-- Invalid reply message!\n");
                    else if(receivedPacket.error == WRONG_VIEW)
                    printf("\n-- Enter a conversation to send message!\n");
                    else { /* nothing! good! */ }
                    fflush(stdout);
                    break;
                }
                case MESSAGE_NOTIFICATION: {
                    printf("\n-- Message [%s] ----------- %s >>> %s (%s)\n%s\n\n", receivedPacket.message.id, receivedPacket.message.sender, receivedPacket.message.receiver, receivedPacket.message.timeStamp, receivedPacket.message.content);
                    fflush(stdout);
                    break;
                }
                case VIEW_ALL_CONVOS_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("\n-- You are not logged in!\n");
                    else
                        printf("\n-- Convo: %s\n", receivedPacket.user.username);
                    fflush(stdout);
                    break;
                }
                case VIEW_CONVERSATION_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("\n-- You are not logged in!\n");
                    else if(receivedPacket.error == INVALID_USER_DATA)
                        printf("\n-- Inexistent user!\n");
                    else
                        printf("\n-- Message [%s] ----------- %s >>> %s (%s)\n%s\n", receivedPacket.message.id, receivedPacket.message.sender, receivedPacket.message.receiver, receivedPacket.message.timeStamp, receivedPacket.message.content);
                    fflush(stdout);
                    break;
                }
                default: {
                    printf("\nFeedback: UNKNOWN!\n");
                    fflush(stdout);
                }
            }
        } else if (bytesReceived <= 0) {
            printf("\nServer disconnected!\n");
            break;
        }
    }
    pthread_exit(NULL);
}

void* userInputThread(void* arg) {
    int clientSocket = *(int*)arg;
    while (1) {
        char userInput[256];
        fgets(userInput, sizeof(userInput), stdin);
        char* params[MAX_WORDS];
        int paramCount = 0;
        strtok(userInput, "\n");
        char* token = strtok(userInput, " ");
        while (token != NULL && paramCount < MAX_WORDS) {
            params[paramCount++] = token;
            token = strtok(NULL, " "); 
        }
        Packet P;
        int okToSend = 1;
        if (paramCount > 0) {
            if (strcmp(params[0], "register") == 0) {
                P.type = REGISTER;
                if(paramCount < 3) {
                    printf("-- Syntax: login <username> <password>\n");
                    okToSend = 0;
                } else {
                    strcpy(P.user.username, params[1]);
                    strcpy(P.user.password, params[2]);
                }
            } else if (strcmp(params[0], "login") == 0) {
                P.type = LOGIN;
                if(paramCount < 3) {
                    printf("-- Syntax: login <username> <password>\n");
                    okToSend = 0;
                } else {     
                    strcpy(P.user.username, params[1]);
                    strcpy(P.user.password, params[2]);
                }
            } else if (strcmp(params[0], "logout") == 0) {
                P.type = LOGOUT;
            } else if (strcmp(params[0], "send") == 0) {
                P.type = SEND_MESSAGE;
                if(paramCount < 2) {
                    printf("-- Syntax: send <content>\n");
                    okToSend = 0;
                } else {
                    strcpy(P.message.replyId, "");
                    strcpy(P.message.content, params[1]);

                    for(int i=2;i<paramCount;i++)
                    {
                        strcat(P.message.content, " ");
                        strcat(P.message.content, params[i]);
                    }
                }
            } else if (strcmp(params[0], "reply") == 0) {
                P.type = SEND_MESSAGE;
                if(paramCount < 3) {
                    printf("-- Syntax: reply <messageId> <content>\n");
                    okToSend = 0;
                } else {
                    strcpy(P.message.replyId, params[1]);
                    strcpy(P.message.content, params[2]);
                    for(int i=3;i<paramCount;i++)
                    {
                        strcat(P.message.content, " ");
                        strcat(P.message.content, params[i]);
                    }
                }
            } else if (strcmp(params[0], "viewallconvos") == 0) {
                P.type = VIEW_ALL_CONVOS;
            } else if (strcmp(params[0], "viewconvo") == 0) {
                P.type = VIEW_CONVERSATION;
                if(paramCount < 2) {
                    printf("-- Syntax: viewconvo <username>\n");
                    okToSend = 0;
                } else
                    strcpy(P.user.username, params[1]);
            } else if (strcmp(params[0], "exit") == 0) {
                printf("disconnecting...\n");
                fflush(stdout);
                exit(0);
            } else if (strcmp(params[0], "help") == 0) {
                printf("login <user> <pass> - login into existing account\n");
                printf("register <user> <pass> - create a new account\n");
                printf("viewallconvos - see all your past conversations\n");
                printf("viewconvo <user> - enter conversation with [user]\n");
                printf("send <message> - send message to the user of the current conversation\n");
                printf("reply <id> <message> - reply to a specific message\n");
                printf("exit - close the app\n");
                okToSend = 0;
            } else {
                printf("-- Unknown command! Type 'help' for a list of commands...\n");
                P.type = EMPTY;
                okToSend = 0;
            }
        }
        if(okToSend)
        {
            unsigned char buffer[sizeof(Packet)];
            encode_vigenere_packet(&P, vigenere_key);
            serializePacket(&P, buffer, sizeof(buffer));
            send(clientSocket, buffer, sizeof(buffer), 0);
        }
    }
    pthread_exit(NULL);
}

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0) {
        perror("invalid address!\n");
        close(clientSocket);
        exit(1);
    }
    
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("error connecting to the server!\n");
        close(clientSocket);
        exit(2);
    }

    pthread_t receiveThreadId, userInputThreadId;
    pthread_create(&receiveThreadId, NULL, receiveThread, (void*)&clientSocket);
    pthread_create(&userInputThreadId, NULL, userInputThread, (void*)&clientSocket);
    pthread_join(receiveThreadId, NULL);
    pthread_join(userInputThreadId, NULL);
    return 0;
}