#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>

#define SERVER_PORT 2024
#define MAX_CLIENTS 256

Connection connectionList[MAX_CLIENTS];

void initializeConnectionList() {
    for(int i=0;i<256;i++)
    {
        connectionList[i].sd = -1;
        strcpy(connectionList[i].username, "");
    }
}

int main() {
    initializeConnectionList();
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("bind error");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    if (listen(serverSocket, 5) == -1) {
        perror("listen error");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    fd_set readfds;
    int maxSocket = serverSocket;
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connectionList[i].sd > 0) {
                FD_SET(connectionList[i].sd, &readfds);
                if (connectionList[i].sd > maxSocket) {
                    maxSocket = connectionList[i].sd;
                }
            }
        }

        if (select(maxSocket + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("select error");
            return EXIT_FAILURE;
        }

        if (FD_ISSET(serverSocket, &readfds)) {
            int newClientSocket = accept(serverSocket, NULL, NULL);
            if (newClientSocket > 0) {
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (connectionList[i].sd == -1) {
                        connectionList[i].sd = newClientSocket;
                        connectionList[i].currentView = LOGIN_VIEW;
                        break;
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connectionList[i].sd > 0 && FD_ISSET(connectionList[i].sd, &readfds)) {
                Packet P1;
                ssize_t bytesReceived = recv(connectionList[i].sd, &P1, sizeof(Packet), 0);
                if (bytesReceived > 0) {
                    switch(P1.type) {
                        case REGISTER: {
                            Packet P2;
                            P2.type = REGISTER_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        case LOGIN: {
                            Packet P2;
                            P2.type = LOGIN_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        case LOGOUT: {
                            Packet P2;
                            P2.type = LOGOUT_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        case SEND_MESSAGE: {
                            Packet P2;
                            P2.type = SEND_MESSAGE_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        case VIEW_ALL_CONVOS: {
                            Packet P2;
                            P2.type = VIEW_ALL_CONVOS_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        case VIEW_CONVERSATION: {
                            Packet P2;
                            P2.type = VIEW_CONVERSATION_RESPONSE;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                            break;
                        }
                        default: {
                            Packet P2;
                            P2.type = EMPTY;
                            P2.error = SUCCESS;
                            send(connectionList[i].sd, &P2, sizeof(Packet), 0);
                        }
                    }
                } else if (bytesReceived <= 0) {
                    close(connectionList[i].sd);
                    connectionList[i].sd = -1;
                    strcpy(connectionList[i].username, "");
                }
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connectionList[i].sd > 0) {
            close(connectionList[i].sd);
        }
    }
    close(serverSocket);
    return 0;
}
