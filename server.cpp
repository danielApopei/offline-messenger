#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sqlite3.h>
#include <iostream>

#define SERVER_PORT 2024
#define MAX_CLIENTS 256

Connection connectionList[MAX_CLIENTS];

void initializeConnectionList() {
    for(int i=0;i<256;i++)
    {
        connectionList[i].sd = -1; // signifies that there is no sd stored here
        strcpy(connectionList[i].username, "");
    }
}

void printConnectionList() {
    printf("list: ");
    for(int i=0;i<256;i++)
    {
        if(connectionList[i].sd != -1)
            printf("%d ", i);
    }
    printf("\n");
}

void handleDbError(int rc, const char* errorMsg) {
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", errorMsg);
        exit(EXIT_FAILURE);
    }
}

int main() {

    // opening database
    sqlite3 *db;
    char *errorMessage = nullptr;
    int rc = sqlite3_open("database.db", &db);
    if (rc != SQLITE_OK)
    {
        std::cerr << "error: cannot open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return rc;
    }

    initializeConnectionList();
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        perror("Error binding socket");
        close(serverSocket);
        return EXIT_FAILURE;
    }
    if (listen(serverSocket, SOMAXCONN) == -1) {
        perror("Error listening for connections");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    fd_set readfds;  // File descriptor set for select
    int maxSocket = serverSocket;

    while (1) {
        printConnectionList();
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);

        // Add all connected client sockets to the set
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connectionList[i].sd > 0) {
                FD_SET(connectionList[i].sd, &readfds);
                if (connectionList[i].sd > maxSocket) {
                    maxSocket = connectionList[i].sd;
                }
            }
        }

        // Use select to monitor sockets for activity
        if (select(maxSocket + 1, &readfds, NULL, NULL, NULL) == -1) {
            perror("Error in select");
            return EXIT_FAILURE;
        }

        // Check for incoming connection
        if (FD_ISSET(serverSocket, &readfds)) {
            int newClientSocket = accept(serverSocket, NULL, NULL);
            if (newClientSocket > 0) {
                // Add the new client to the connection list
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (connectionList[i].sd == -1) {
                        connectionList[i].sd = newClientSocket;
                        connectionList[i].currentView = LOGIN_VIEW;
                        // Optionally, set other information about the client (e.g., username)
                        break;
                    }
                }
            }
        }

        // Check data from clients
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connectionList[i].sd > 0 && FD_ISSET(connectionList[i].sd, &readfds)) {
                Packet receivedPacket;
                ssize_t bytesReceived = recv(connectionList[i].sd, &receivedPacket, sizeof(Packet), 0);
                if (bytesReceived > 0) {
                    switch(receivedPacket.type) {
                        case REGISTER: {
                            printf("register received!\n");

                            // Check if username already exists in the database
                            const char* checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                            sqlite3_stmt* checkUserStmt;

                            int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                            handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                            rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind username parameter for checking user existence");
                            int userCount = 0;
                            rc = sqlite3_step(checkUserStmt);
                            if (rc == SQLITE_ROW) {
                                userCount = sqlite3_column_int(checkUserStmt, 0);
                            }

                            sqlite3_finalize(checkUserStmt);

                            // If the username already exists, send USER_ALREADY_EXISTS response
                            if (userCount > 0) {
                                Packet responsePacket;
                                responsePacket.type = REGISTER_RESPONSE;
                                responsePacket.error = USER_ALREADY_EXISTS;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else {
                                // Insert new user into the database
                                const char* insertUserQuery = "INSERT INTO Users (username, password) VALUES (?, ?);";
                                sqlite3_stmt* insertUserStmt;

                                rc = sqlite3_prepare_v2(db, insertUserQuery, -1, &insertUserStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for user registration");

                                rc = sqlite3_bind_text(insertUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind username parameter for user registration");
                                rc = sqlite3_bind_text(insertUserStmt, 2, receivedPacket.user.password, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind password parameter for user registration");

                                rc = sqlite3_step(insertUserStmt);
                                sqlite3_finalize(insertUserStmt);

                                strcpy(connectionList[i].username, receivedPacket.user.username);
                                connectionList[i].currentView = MAIN_VIEW;

                                // Send SUCCESS response
                                Packet responsePacket;
                                responsePacket.type = REGISTER_RESPONSE;
                                responsePacket.error = SUCCESS;
                                strcpy(responsePacket.user.username, connectionList[i].username);
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            }

                            break;
                        }
                        case LOGIN: {
                            printf("login received!\n");

                            // Check if username and password combination exists in the database
                            const char* checkLoginQuery = "SELECT COUNT(*) FROM Users WHERE username = ? AND password = ?;";
                            sqlite3_stmt* checkLoginStmt;

                            int rc = sqlite3_prepare_v2(db, checkLoginQuery, -1, &checkLoginStmt, NULL);
                            handleDbError(rc, "Failed to prepare SQL statement for checking login");

                            rc = sqlite3_bind_text(checkLoginStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind username parameter for checking login");
                            rc = sqlite3_bind_text(checkLoginStmt, 2, receivedPacket.user.password, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind password parameter for checking login");

                            int loginCount = 0;
                            rc = sqlite3_step(checkLoginStmt);
                            if (rc == SQLITE_ROW) {
                                loginCount = sqlite3_column_int(checkLoginStmt, 0);
                            }

                            sqlite3_finalize(checkLoginStmt);

                            int foundAnother = 0;
                            for(int i=0;i<MAX_CLIENTS;i++) {
                                if(strcmp(connectionList[i].username, receivedPacket.user.username) == 0)
                                    foundAnother = 1;
                            }

                            // If the login combination is correct, mark connectionList[i].username and send LOGIN_RESPONSE SUCCESS
                            if (loginCount < 1) {
                                // If the login combination is incorrect, send LOGIN_RESPONSE INVALID_USER_DATA
                                Packet responsePacket;
                                responsePacket.type = LOGIN_RESPONSE;
                                responsePacket.error = INVALID_USER_DATA;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else if (foundAnother == 1) {
                                Packet responsePacket;
                                responsePacket.type = LOGIN_RESPONSE;
                                responsePacket.error = USER_ALREADY_CONNECTED;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else {
                                // Mark connectionList[i].username
                                strcpy(connectionList[i].username, receivedPacket.user.username);

                                // Send SUCCESS response
                                Packet responsePacket;
                                responsePacket.type = LOGIN_RESPONSE;
                                responsePacket.error = SUCCESS;
                                connectionList[i].currentView = MAIN_VIEW;
                                strcpy(connectionList[i].username, receivedPacket.user.username);
                                strcpy(responsePacket.user.username, connectionList[i].username);
                                printf("sending welcome: [%s]", responsePacket.user.username);
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            }
                            break;
                        }
                        case LOGOUT: {
                            printf("logout received!\n");
                            if(strcmp(connectionList[i].username, "") == 0)
                            {
                                // user is not logged in, send error through Packet
                                Packet responsePacket;
                                responsePacket.type = LOGOUT_RESPONSE;
                                responsePacket.error = NOT_LOGGED_IN;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            }
                            else
                            {
                                Packet responsePacket;
                                strcpy(responsePacket.user.username, connectionList[i].username);
                                strcpy(connectionList[i].username, "");
                                connectionList[i].currentView = LOGIN_VIEW;
                                responsePacket.type = LOGOUT_RESPONSE;
                                responsePacket.error = SUCCESS;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            }
                            break;
                        }
                        case SEND_MESSAGE: {
                            int okToAdd = 1;
                            printf("send_message received!\n");
                            char replyContent[CONTENT_LENGTH];
                            memset(replyContent, 0, sizeof(replyContent));
                            strcpy(receivedPacket.message.receiver, connectionList[i].viewingConvo);
                            // Check if the sender is logged in
                            if (strcmp(connectionList[i].username, "") == 0) {
                                Packet responsePacket;
                                responsePacket.type = SEND_MESSAGE_RESPONSE;
                                responsePacket.error = NOT_LOGGED_IN;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else {
                                // Check if the receiver username exists in the Users table
                                const char* checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                                sqlite3_stmt* checkUserStmt;

                                int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                                rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind receiver username parameter for checking user existence");

                                int userCount = 0;
                                rc = sqlite3_step(checkUserStmt);
                                if (rc == SQLITE_ROW) {
                                    userCount = sqlite3_column_int(checkUserStmt, 0);
                                }

                                sqlite3_finalize(checkUserStmt);

                                // If the receiver username does not exist, send SEND_MESSAGE_RESPONSE INVALID_USER_DATA
                                if (userCount == 0) {
                                    Packet responsePacket;
                                    responsePacket.type = SEND_MESSAGE_RESPONSE;
                                    responsePacket.error = INVALID_USER_DATA;
                                    send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                } else {
                                    if (receivedPacket.message.replyId[0] != '\0') {
                                        // Check if the reply ID exists in the Messages table and is part of the same conversation
                                        const char* checkReplyQuery = "SELECT content FROM Messages WHERE id = ? AND ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?));";
                                        sqlite3_stmt* checkReplyStmt;
                                        rc = sqlite3_prepare_v2(db, checkReplyQuery, -1, &checkReplyStmt, NULL);
                                        handleDbError(rc, "Failed to prepare SQL statement for checking reply ID existence");

                                        rc = sqlite3_bind_text(checkReplyStmt, 1, receivedPacket.message.replyId, -1, SQLITE_STATIC);
                                        handleDbError(rc, "Failed to bind reply ID parameter for checking reply ID existence");
                                        rc = sqlite3_bind_text(checkReplyStmt, 2, connectionList[i].username, -1, SQLITE_STATIC);
                                        handleDbError(rc, "Failed to bind sender parameter for checking reply ID existence");
                                        rc = sqlite3_bind_text(checkReplyStmt, 3, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                        handleDbError(rc, "Failed to bind receiver parameter for checking reply ID existence");
                                        rc = sqlite3_bind_text(checkReplyStmt, 4, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                        handleDbError(rc, "Failed to bind sender parameter for checking reply ID existence");
                                        rc = sqlite3_bind_text(checkReplyStmt, 5, connectionList[i].username, -1, SQLITE_STATIC);
                                        handleDbError(rc, "Failed to bind receiver parameter for checking reply ID existence");
                                        rc = sqlite3_step(checkReplyStmt);
                                        if (rc == SQLITE_ROW) {
                                            const char* originalContent = (const char*)sqlite3_column_text(checkReplyStmt, 0);
                                            strcat(replyContent, "\n");  // Add a newline for separation
                                            strcat(replyContent, originalContent);
                                        } else {
                                            okToAdd = 0;
                                            // Reply ID does not exist in the same conversation, send SEND_MESSAGE_RESPONSE INVALID_REPLY_ID
                                            Packet responsePacket;
                                            responsePacket.type = SEND_MESSAGE_RESPONSE;
                                            responsePacket.error = INVALID_REPLY_ID;
                                            send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                        }
                                        if(checkReplyStmt != NULL)
                                            sqlite3_finalize(checkReplyStmt);
                                    }
                                    if(okToAdd) {
                                    // Insert the message into the Messages table
                                    const char* insertMessageQuery = "INSERT INTO Messages (sender, receiver, content, timeStamp, replyId, isDeleted) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, 0);";
                                    sqlite3_stmt* insertMessageStmt;
                                    if (receivedPacket.message.replyId[0] != '\0')
                                        strcat(receivedPacket.message.content, replyContent);
                                    rc = sqlite3_prepare_v2(db, insertMessageQuery, -1, &insertMessageStmt, NULL);
                                    handleDbError(rc, "Failed to prepare SQL statement for message insertion");
                                    strcpy(receivedPacket.message.sender, connectionList[i].username);
                                    rc = sqlite3_bind_text(insertMessageStmt, 1, receivedPacket.message.sender, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind sender parameter for message insertion");
                                    rc = sqlite3_bind_text(insertMessageStmt, 2, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind receiver parameter for message insertion");
                                    rc = sqlite3_bind_text(insertMessageStmt, 3, receivedPacket.message.content, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind content parameter for message insertion");
                                    
                                    if (strcmp(receivedPacket.message.replyId, "") == 0) {
                                        // Bind NULL for reply ID
                                        rc = sqlite3_bind_null(insertMessageStmt, 4);
                                    } else {
                                        // Convert the reply ID to an integer and bind it
                                        rc = sqlite3_bind_int(insertMessageStmt, 4, atoi(receivedPacket.message.replyId));
                                    }
                                    handleDbError(rc, "Failed to bind reply ID parameter for message insertion");

                                    rc = sqlite3_step(insertMessageStmt);
                                    if (rc == SQLITE_DONE) {
                                        // The SQL statement has executed successfully

                                        // Get the last inserted row ID (message ID)
                                        int messageId = sqlite3_last_insert_rowid(db);

                                        // Convert the integer to a string and copy it to the receivedPacket.message.id field
                                        sprintf(receivedPacket.message.id, "%d", messageId);
                                        printf("inserted: %s\n", receivedPacket.message.id);

                                        // If the receiver is currently connected, send the message via a Packet
                                        int found = -1;
                                        for (int j = 0; j < MAX_CLIENTS; j++) {
                                            if (strcmp(connectionList[j].username, receivedPacket.message.receiver) == 0 && strcmp(connectionList[j].viewingConvo, connectionList[i].username) == 0) {
                                                found = j;
                                                break;
                                            }
                                        }
                                        if (found != -1) {
                                            Packet destPacket;
                                            destPacket.type = MESSAGE_NOTIFICATION;
                                            strcpy(destPacket.message.id, receivedPacket.message.id);
                                            strcpy(destPacket.message.sender, connectionList[i].username);
                                            strcpy(destPacket.message.receiver, connectionList[found].username);
                                            strcpy(destPacket.message.content, receivedPacket.message.content);

                                            const char* getTimeQuery = "SELECT CURRENT_TIMESTAMP FROM Messages;";
                                            sqlite3_stmt* getTimeStmt;

                                            rc = sqlite3_prepare_v2(db, getTimeQuery, -1, &getTimeStmt, NULL);
                                            handleDbError(rc, "Failed to prepare SQL statement for getting current timestamp");

                                            // Execute the query to get the current timestamp
                                            rc = sqlite3_step(getTimeStmt);

                                            // Check if the query was successful
                                            if (rc == SQLITE_ROW) {
                                                // Retrieve the timestamp from the result
                                                const char* currentTimestamp = (const char*)sqlite3_column_text(getTimeStmt, 0);

                                                // Now, 'currentTimestamp' contains the current timestamp
                                                printf("Current Timestamp: %s\n", currentTimestamp);
                                                strcpy(destPacket.message.timeStamp, currentTimestamp);
                                                // You can store 'currentTimestamp' in a variable or use it as needed
                                            } else {
                                                // Handle the case where the query did not return a row
                                                printf("Failed to retrieve current timestamp.\n");
                                            }

                                            // Finalize the statement
                                            sqlite3_finalize(getTimeStmt);

                                            send(connectionList[found].sd, &destPacket, sizeof(Packet), 0);
                                        }

                                        // Send SEND_MESSAGE_RESPONSE SUCCESS
                                        Packet responsePacket;
                                        responsePacket.type = SEND_MESSAGE_RESPONSE;
                                        responsePacket.error = SUCCESS;
                                        send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                    } else {
                                        // Handle the case where an error occurred during execution
                                        printf("Failed to insert message into the database.\n");
                                    }

                                    sqlite3_finalize(insertMessageStmt);
                                    }
                                }
                            }

                            break;
                        }



                        case VIEW_ALL_CONVOS: {
                            printf("view_all_convos received!\n");

                            // Check if the sender is logged in
                            if (strcmp(connectionList[i].username, "") == 0) {
                                Packet responsePacket;
                                responsePacket.type = VIEW_ALL_CONVOS_RESPONSE;
                                responsePacket.error = NOT_LOGGED_IN;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else {
                                strcpy(connectionList[i].viewingConvo, "");
                                connectionList[i].currentView = MAIN_VIEW;
                                // Select all unique participants where the current user is either the sender or receiver
                                const char* selectParticipantsQuery = "SELECT DISTINCT participant FROM ("
                                                                    "    SELECT sender AS participant FROM Messages WHERE receiver = ?"
                                                                    "    UNION"
                                                                    "    SELECT receiver AS participant FROM Messages WHERE sender = ?"
                                                                    ");";
                                sqlite3_stmt* selectParticipantsStmt;

                                int rc = sqlite3_prepare_v2(db, selectParticipantsQuery, -1, &selectParticipantsStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for selecting participants");

                                rc = sqlite3_bind_text(selectParticipantsStmt, 1, connectionList[i].username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind username parameter for selecting participants");

                                rc = sqlite3_bind_text(selectParticipantsStmt, 2, connectionList[i].username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind username parameter for selecting participants");

                                // Iterate over the results and send each participant through VIEW_ALL_CONVOS_RESPONSE packet
                                while ((rc = sqlite3_step(selectParticipantsStmt)) == SQLITE_ROW) {
                                    const char* participant = (const char*)sqlite3_column_text(selectParticipantsStmt, 0);

                                    Packet responsePacket;
                                    responsePacket.type = VIEW_ALL_CONVOS_RESPONSE;
                                    strcpy(responsePacket.user.username, participant);
                                    send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                }

                                sqlite3_finalize(selectParticipantsStmt);
                            }

                            break;
                        }

                        case VIEW_CONVERSATION: {
                            printf("view_convo received!\n");

                            // Check if the user is logged in
                            if (strcmp(connectionList[i].username, "") == 0) {
                                Packet responsePacket;
                                responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                                responsePacket.error = NOT_LOGGED_IN;
                                send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                            } else {
                                // Check if the provided username is in the Users table
                                const char* checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                                sqlite3_stmt* checkUserStmt;

                                int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                                rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind username parameter for checking user existence");

                                int userCount = 0;
                                rc = sqlite3_step(checkUserStmt);
                                if (rc == SQLITE_ROW) {
                                    userCount = sqlite3_column_int(checkUserStmt, 0);
                                }
                                sqlite3_finalize(checkUserStmt);

                                // If the provided username does not exist, send VIEW_CONVERSATION_RESPONSE INVALID_USER_DATA
                                if (userCount == 0) {
                                    Packet responsePacket;
                                    responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                                    responsePacket.error = INVALID_USER_DATA;
                                    send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                } else {
                                    connectionList[i].currentView = CONVERSATION_VIEW;
                                    strcpy(connectionList[i].viewingConvo, receivedPacket.user.username);
                                    // Retrieve all messages exchanged between the two users
                                    const char* selectMessagesQuery = "SELECT id, sender, receiver, content, timeStamp FROM Messages WHERE "
                                                                    "(sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timeStamp;";
                                    sqlite3_stmt* selectMessagesStmt;

                                    rc = sqlite3_prepare_v2(db, selectMessagesQuery, -1, &selectMessagesStmt, NULL);
                                    handleDbError(rc, "Failed to prepare SQL statement for selecting messages");

                                    rc = sqlite3_bind_text(selectMessagesStmt, 1, connectionList[i].username, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind sender parameter for selecting messages");

                                    rc = sqlite3_bind_text(selectMessagesStmt, 2, receivedPacket.user.username, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind receiver parameter for selecting messages");

                                    rc = sqlite3_bind_text(selectMessagesStmt, 3, receivedPacket.user.username, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind sender parameter for selecting messages");

                                    rc = sqlite3_bind_text(selectMessagesStmt, 4, connectionList[i].username, -1, SQLITE_STATIC);
                                    handleDbError(rc, "Failed to bind receiver parameter for selecting messages");

                                    // Iterate over the results and send each message through VIEW_CONVERSATION_RESPONSE packet
                                    while ((rc = sqlite3_step(selectMessagesStmt)) == SQLITE_ROW) {
                                        const char* id = (const char*) sqlite3_column_text(selectMessagesStmt, 0);
                                        const char* sender = (const char*)sqlite3_column_text(selectMessagesStmt, 1);
                                        const char* receiver = (const char*)sqlite3_column_text(selectMessagesStmt, 2);
                                        const char* content = (const char*)sqlite3_column_text(selectMessagesStmt, 3);
                                        const char* timeStamp = (const char*)sqlite3_column_text(selectMessagesStmt, 4);

                                        Packet responsePacket;
                                        responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                                        responsePacket.error = SUCCESS;
                                        strcpy(responsePacket.message.id, id);
                                        strcpy(responsePacket.message.sender, sender);
                                        strcpy(responsePacket.message.receiver, receiver);
                                        strcpy(responsePacket.message.content, content);
                                        strcpy(responsePacket.message.timeStamp, timeStamp);
                                        
                                        send(connectionList[i].sd, &responsePacket, sizeof(Packet), 0);
                                    }

                                    sqlite3_finalize(selectMessagesStmt);
                                }
                            }
                            break;
                        }
                        default: {
                            printf("unknown received!\n");
                        }
                    }
                } else if (bytesReceived == 0 || (bytesReceived == -1 && errno != EWOULDBLOCK && errno != EAGAIN)) {
                    // client closed connection
                    printf("Client %s disconnected.\n", connectionList[i].username);
                    close(connectionList[i].sd);
                    connectionList[i].sd = -1;
                    strcpy(connectionList[i].username, ""); // Optionally, clear other client information
                }
            }
        }
    }

    // Close all client sockets and the server socket
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connectionList[i].sd > 0) {
            close(connectionList[i].sd);
        }
    }
    close(serverSocket);
    return 0;
}