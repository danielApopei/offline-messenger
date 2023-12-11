#include "structures.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 2024
#define MAX_WORDS 32

void* receiveThread(void* arg) {
    int clientSocket = *(int*)arg;
    while (1) {
        Packet receivedPacket;
        ssize_t bytesReceived = recv(clientSocket, &receivedPacket, sizeof(Packet), 0);

        if (bytesReceived > 0) {
            // Process and print the received message immediately
            switch(receivedPacket.type) {
                case REGISTER_RESPONSE: {
                    if(receivedPacket.error == USER_ALREADY_EXISTS)
                        printf("-- user already exists!\n");
                    else
                        printf("-- welcome, %s!\n", receivedPacket.user.username);
                    break;
                }
                case LOGIN_RESPONSE: {
                    if(receivedPacket.error == INVALID_USER_DATA)
                        printf("-- wrong username-password combination!\n");
                    else if(receivedPacket.error == USER_ALREADY_CONNECTED)
                        printf("-- user is already connected on a different device!\n");
                    else
                        printf("-- welcome, %s!\n", receivedPacket.user.username);
                    break;
                }
                case LOGOUT_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("-- you are not logged in!\n");
                    else
                        printf("-- goodbye, %s!\n", receivedPacket.user.username);
                    break;
                }
                case SEND_MESSAGE_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("-- you are not logged in!\n");
                    else if(receivedPacket.error == INVALID_USER_DATA)
                        printf("-- no such user!\n");
                    else if(receivedPacket.error == INVALID_REPLY_ID)
                    printf("-- invalid reply message!\n");
                    else
                        printf("-- sent!\n");
                    break;
                }
                case MESSAGE_NOTIFICATION: {
                    printf("-- message with id %s: %s to %s at %s: %s\n", receivedPacket.message.id, receivedPacket.message.sender, receivedPacket.message.receiver, receivedPacket.message.timeStamp, receivedPacket.message.content);
                    fflush(stdout);
                    break;
                }
                case VIEW_ALL_CONVOS_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("-- you are not logged in!\n");
                    else
                        printf("-- convo: %s\n", receivedPacket.user.username);
                    fflush(stdout);
                    break;
                }
                case VIEW_CONVERSATION_RESPONSE: {
                    if(receivedPacket.error == NOT_LOGGED_IN)
                        printf("-- you are not logged in!\n");
                    else
                        printf("-- message with id %s: %s to %s at %s: %s\n", receivedPacket.message.id, receivedPacket.message.sender, receivedPacket.message.receiver, receivedPacket.message.timeStamp, receivedPacket.message.content);
                    fflush(stdout);
                    break;
                }
                default: {
                    printf("-- received unknown!\n");
                }
            }
        } else if (bytesReceived == 0 || (bytesReceived == -1 && errno != EWOULDBLOCK && errno != EAGAIN)) {
            // The server has closed the connection or an error occurred
            printf("-- Server disconnected.\n");
        
            break;
        }
    }
    pthread_exit(NULL);
}

void* userInputThread(void* arg) {
    int clientSocket = *(int*)arg;
    while (1) {
        // Get user input
        char userInput[256];
        fgets(userInput, sizeof(userInput), stdin);
        strtok(userInput, "\n"); // Remove the newline character

        // Split userInput into words
        char* params[MAX_WORDS];
        int paramCount = 0;

        char* token = strtok(userInput, " ");
        while (token != NULL && paramCount < MAX_WORDS) {
            params[paramCount++] = token;
            token = strtok(NULL, " ");
        }

        // Create a Packet and set the appropriate type based on the first parameter
        Packet userPacket;
        int okToSend = 1;
        if (paramCount > 0) {
            // Set the type based on the first parameter
            if (strcmp(params[0], "register") == 0) {
                userPacket.type = REGISTER;
                if(paramCount < 3) {
                    printf("syntax: login <username> <password>");
                    okToSend = 0;
                } else {
                    strcpy(userPacket.user.username, params[1]);
                    strcpy(userPacket.user.password, params[2]);
                }
            } else if (strcmp(params[0], "login") == 0) {
                userPacket.type = LOGIN;
                if(paramCount < 3) {
                    printf("syntax: login <username> <password>");
                    okToSend = 0;
                } else {
                    printf("reached A\n");      
                    strcpy(userPacket.user.username, params[1]);
                    strcpy(userPacket.user.password, params[2]);
                }
            } else if (strcmp(params[0], "logout") == 0) {
                userPacket.type = LOGOUT;
            } else if (strcmp(params[0], "send") == 0) {
                userPacket.type = SEND_MESSAGE;
                if(paramCount < 2) {
                    printf("syntax: send <content>");
                    okToSend = 0;
                } else {
                    strcpy(userPacket.message.replyId, "");
                    strcpy(userPacket.message.content, params[1]);

                    for(int i=2;i<paramCount;i++)
                    {
                        strcat(userPacket.message.content, " ");
                        strcat(userPacket.message.content, params[i]);
                    }
                }
            } else if (strcmp(params[0], "reply") == 0) {
                userPacket.type = SEND_MESSAGE;
                if(paramCount < 3) {
                    printf("syntax: reply <messageId> <content>");
                    okToSend = 0;
                } else {
                    strcpy(userPacket.message.replyId, params[1]);
                    strcpy(userPacket.message.content, params[2]);
                    for(int i=3;i<paramCount;i++)
                    {
                        strcat(userPacket.message.content, " ");
                        strcat(userPacket.message.content, params[i]);
                    }
                }
            } else if (strcmp(params[0], "viewallconvos") == 0) {
                userPacket.type = VIEW_ALL_CONVOS;
            } else if (strcmp(params[0], "viewconvo") == 0) {
                userPacket.type = VIEW_CONVERSATION;
                if(paramCount < 2) {
                    printf("syntax: viewconvo <username>");
                    okToSend = 0;
                } else
                    strcpy(userPacket.user.username, params[1]);
            } else if (strcmp(params[0], "exit") == 0) {
                exit(EXIT_SUCCESS);
            } else {
                printf("unknown command!\n");
                userPacket.type = EMPTY;
                okToSend = 0;
            }
        }

        if(userPacket.type == EMPTY)
            okToSend = 0;

        // Populate the rest of the userPacket with relevant data based on user input
        // ...
        printf("okToSend: %d\n", okToSend);
        // Send the userPacket to the server
        if(okToSend)
            send(clientSocket, &userPacket, sizeof(Packet), 0);
    }
    pthread_exit(NULL);
}

int main() {
    // creating socket connection with server
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &serverAddress.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(clientSocket);
        return EXIT_FAILURE;
    }
    // connect to the server
    if (connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Error connecting to the server");
        close(clientSocket);
        return EXIT_FAILURE;
    }

    // creating the two threads
    pthread_t receiveThreadId, userInputThreadId;
    pthread_create(&receiveThreadId, NULL, receiveThread, (void*)&clientSocket);
    pthread_create(&userInputThreadId, NULL, userInputThread, (void*)&clientSocket);
    pthread_join(receiveThreadId, NULL);
    pthread_join(userInputThreadId, NULL);
    return 0;
}