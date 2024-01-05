
#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <pthread.h>
#include <sqlite3.h>

#define SERVER_PORT 2024
#define MAX_CLIENTS 256

Connection connectionList[MAX_CLIENTS];
pthread_mutex_t connectionListMutex = PTHREAD_MUTEX_INITIALIZER;
sqlite3 *db;

void initializeConnectionList() {
    for(int i = 0; i < MAX_CLIENTS; i++)
    {
        connectionList[i].sd = -1;
        strcpy(connectionList[i].username, "");
    }
}

void printConnectionList()
{
    pthread_mutex_lock(&connectionListMutex);
    printf("list: ");
    for (int i = 0; i < 256; i++)
    {
        if (connectionList[i].sd != -1) {
            printf("(%d, %d, %s) ", i, connectionList[i].sd, connectionList[i].username);
        }
    }
    printf("\n");
    pthread_mutex_unlock(&connectionListMutex);
}

void handleDbError(int rc, const char *errorMsg)
{
    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQLite error: %s\n", errorMsg);
        exit(EXIT_FAILURE);
    }
}

// Function to handle client communication in a separate thread
void* clientHandler(void* args) {
    int* arguments = (int*)args;
    int clientSocket = arguments[0];
    int connectionIndex = arguments[1];
    free(args);
    // Placeholder for client communication logic
    // This should handle the communication with the client using clientSocket
    // and manage the client's data in connectionList[connectionIndex]
    while(1) {
        printConnectionList();
        Packet receivedPacket;
        unsigned char receivedBuffer[sizeof(Packet)];
        ssize_t bytesReceived = recv(clientSocket, receivedBuffer, sizeof(receivedBuffer), 0);
        xorEncryptDecrypt(receivedBuffer, sizeof(receivedBuffer), key);
        deserializePacket(receivedBuffer, &receivedPacket);
        if (bytesReceived > 0) {
            switch(receivedPacket.type) {
                case REGISTER: {
                    printf("register received!\n");

                    // Check if username already exists in the database
                    const char *checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                    sqlite3_stmt *checkUserStmt;

                    int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                    handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                    rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                    handleDbError(rc, "Failed to bind username parameter for checking user existence");
                    int userCount = 0;
                    rc = sqlite3_step(checkUserStmt);
                    if (rc == SQLITE_ROW)
                    {
                        userCount = sqlite3_column_int(checkUserStmt, 0);
                    }

                    sqlite3_finalize(checkUserStmt);

                    // If the username already exists, send USER_ALREADY_EXISTS response
                    if (userCount > 0)
                    {
                        Packet responsePacket;
                        responsePacket.type = REGISTER_RESPONSE;
                        responsePacket.error = USER_ALREADY_EXISTS;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        // Insert new user into the database
                        const char *insertUserQuery = "INSERT INTO Users (username, password) VALUES (?, ?);";
                        sqlite3_stmt *insertUserStmt;

                        rc = sqlite3_prepare_v2(db, insertUserQuery, -1, &insertUserStmt, NULL);
                        handleDbError(rc, "Failed to prepare SQL statement for user registration");

                        rc = sqlite3_bind_text(insertUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind username parameter for user registration");
                        // encoding pass before
                        char encryptedPass[256];
                        strcpy(encryptedPass, receivedPacket.user.password);
                        encode_vigenere(encryptedPass, vigenere_key);

                        rc = sqlite3_bind_text(insertUserStmt, 2, encryptedPass, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind password parameter for user registration");

                        rc = sqlite3_step(insertUserStmt);
                        sqlite3_finalize(insertUserStmt);
                        pthread_mutex_lock(&connectionListMutex);
                        strcpy(connectionList[connectionIndex].username, receivedPacket.user.username);
                        connectionList[connectionIndex].currentView = MAIN_VIEW;

                        // Send SUCCESS response
                        Packet responsePacket;
                        responsePacket.type = REGISTER_RESPONSE;
                        responsePacket.error = SUCCESS;
                        strcpy(responsePacket.user.username, connectionList[connectionIndex].username);
                        pthread_mutex_unlock(&connectionListMutex);
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }

                    break;
                }
                case LOGIN: {
                    printf("login received!\n");

                    // Check if username and password combination exists in the database
                    const char *checkLoginQuery = "SELECT COUNT(*) FROM Users WHERE username = ? AND password = ?;";
                    sqlite3_stmt *checkLoginStmt;

                    int rc = sqlite3_prepare_v2(db, checkLoginQuery, -1, &checkLoginStmt, NULL);
                    handleDbError(rc, "Failed to prepare SQL statement for checking login");

                    rc = sqlite3_bind_text(checkLoginStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                    handleDbError(rc, "Failed to bind username parameter for checking login");
                    // encoding pass before
                    char encryptedPass[256];
                    strcpy(encryptedPass, receivedPacket.user.password);
                    encode_vigenere(encryptedPass, vigenere_key);
                    rc = sqlite3_bind_text(checkLoginStmt, 2, encryptedPass, -1, SQLITE_STATIC);
                    handleDbError(rc, "Failed to bind password parameter for checking login");

                    int loginCount = 0;
                    rc = sqlite3_step(checkLoginStmt);
                    if (rc == SQLITE_ROW)
                    {
                        loginCount = sqlite3_column_int(checkLoginStmt, 0);
                    }

                    sqlite3_finalize(checkLoginStmt);
                    pthread_mutex_lock(&connectionListMutex);
                    int foundAnother = 0;
                    for (int i = 0; i < MAX_CLIENTS; i++)
                    {
                        if (strcmp(connectionList[i].username, receivedPacket.user.username) == 0)
                            foundAnother = 1;
                    }
                    pthread_mutex_unlock(&connectionListMutex);
                    // If the login combination is correct, mark connectionList[i].username and send LOGIN_RESPONSE SUCCESS
                    if (loginCount < 1)
                    {
                        // If the login combination is incorrect, send LOGIN_RESPONSE INVALID_USER_DATA
                        Packet responsePacket;
                        responsePacket.type = LOGIN_RESPONSE;
                        responsePacket.error = INVALID_USER_DATA;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else if (foundAnother == 1)
                    {
                        Packet responsePacket;
                        responsePacket.type = LOGIN_RESPONSE;
                        responsePacket.error = USER_ALREADY_CONNECTED;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        // Mark connectionList[i].username
                        strcpy(connectionList[connectionIndex].username, receivedPacket.user.username);

                        // Send SUCCESS response
                        Packet responsePacket;
                        responsePacket.type = LOGIN_RESPONSE;
                        responsePacket.error = SUCCESS;
                        pthread_mutex_lock(&connectionListMutex);
                        connectionList[connectionIndex].currentView = MAIN_VIEW;
                        strcpy(connectionList[connectionIndex].username, receivedPacket.user.username);
                        strcpy(responsePacket.user.username, connectionList[connectionIndex].username);
                        printf("sending welcome: [%s]", responsePacket.user.username);
                        pthread_mutex_unlock(&connectionListMutex);
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    break;
                }
                case LOGOUT: {
                    printf("logout received!\n");
                    if (strcmp(connectionList[connectionIndex].username, "") == 0)
                    {
                        // user is not logged in, send error through Packet
                        Packet responsePacket;
                        responsePacket.type = LOGOUT_RESPONSE;
                        responsePacket.error = NOT_LOGGED_IN;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        Packet responsePacket;
                        pthread_mutex_lock(&connectionListMutex);
                        strcpy(responsePacket.user.username, connectionList[connectionIndex].username);
                        strcpy(connectionList[connectionIndex].username, "");
                        connectionList[connectionIndex].currentView = LOGIN_VIEW;
                        responsePacket.type = LOGOUT_RESPONSE;
                        responsePacket.error = SUCCESS;
                        pthread_mutex_unlock(&connectionListMutex);
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    break;
                }
                case SEND_MESSAGE: {
                    int okToAdd = 1;
                    printf("send_message received!\n");
                    char replyContent[CONTENT_LENGTH];
                    memset(replyContent, 0, sizeof(replyContent));
                    pthread_mutex_lock(&connectionListMutex);
                    strcpy(receivedPacket.message.receiver, connectionList[connectionIndex].viewingConvo);
                    pthread_mutex_unlock(&connectionListMutex);
                    // Check if the sender is logged in
                    if (connectionList[connectionIndex].currentView != CONVERSATION_VIEW)
                    {
                        Packet responsePacket;
                        responsePacket.type = SEND_MESSAGE_RESPONSE;
                        responsePacket.error = WRONG_VIEW;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else if (strcmp(connectionList[connectionIndex].username, "") == 0)
                    {
                        Packet responsePacket;
                        responsePacket.type = SEND_MESSAGE_RESPONSE;
                        responsePacket.error = NOT_LOGGED_IN;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        // Check if the receiver username exists in the Users table
                        const char *checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                        sqlite3_stmt *checkUserStmt;

                        int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                        handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                        rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind receiver username parameter for checking user existence");

                        int userCount = 0;
                        rc = sqlite3_step(checkUserStmt);
                        if (rc == SQLITE_ROW)
                        {
                            userCount = sqlite3_column_int(checkUserStmt, 0);
                        }

                        sqlite3_finalize(checkUserStmt);

                        // If the receiver username does not exist, send SEND_MESSAGE_RESPONSE INVALID_USER_DATA
                        if (userCount == 0)
                        {
                            Packet responsePacket;
                            responsePacket.type = SEND_MESSAGE_RESPONSE;
                            responsePacket.error = INVALID_USER_DATA;
                            unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                        }
                        else
                        {
                            if (receivedPacket.message.replyId[0] != '\0')
                            {
                                pthread_mutex_lock(&connectionListMutex);
                                // Check if the reply ID exists in the Messages table and is part of the same conversation
                                const char *checkReplyQuery = "SELECT content FROM Messages WHERE id = ? AND ((sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?));";
                                sqlite3_stmt *checkReplyStmt;
                                rc = sqlite3_prepare_v2(db, checkReplyQuery, -1, &checkReplyStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for checking reply ID existence");

                                rc = sqlite3_bind_text(checkReplyStmt, 1, receivedPacket.message.replyId, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind reply ID parameter for checking reply ID existence");
                                rc = sqlite3_bind_text(checkReplyStmt, 2, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind sender parameter for checking reply ID existence");
                                rc = sqlite3_bind_text(checkReplyStmt, 3, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind receiver parameter for checking reply ID existence");
                                rc = sqlite3_bind_text(checkReplyStmt, 4, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind sender parameter for checking reply ID existence");
                                rc = sqlite3_bind_text(checkReplyStmt, 5, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind receiver parameter for checking reply ID existence");
                                rc = sqlite3_step(checkReplyStmt);
                                pthread_mutex_unlock(&connectionListMutex);
                                if (rc == SQLITE_ROW)
                                {
                                    const char *originalContent = (const char *)sqlite3_column_text(checkReplyStmt, 0);
                                    sprintf(replyContent, "REPLY TO: '%s'\0", originalContent);
                                }
                                else
                                {
                                    okToAdd = 0;
                                    // Reply ID does not exist in the same conversation, send SEND_MESSAGE_RESPONSE INVALID_REPLY_ID
                                    Packet responsePacket;
                                    responsePacket.type = SEND_MESSAGE_RESPONSE;
                                    responsePacket.error = INVALID_REPLY_ID;
                                    unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                                }
                                if (checkReplyStmt != NULL)
                                    sqlite3_finalize(checkReplyStmt);
                            }
                            if (okToAdd)
                            {
                                pthread_mutex_lock(&connectionListMutex);
                                // Insert the message into the Messages table
                                const char *insertMessageQuery = "INSERT INTO Messages (sender, receiver, content, timeStamp, replyId, isDeleted) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, 0);";
                                sqlite3_stmt *insertMessageStmt;
                                if (receivedPacket.message.replyId[0] != '\0')
                                {
                                    char aux[CONTENT_LENGTH];
                                    memset(aux, 0, sizeof(aux));
                                    strcpy(aux, receivedPacket.message.content);
                                    memset(receivedPacket.message.content, 0, sizeof(receivedPacket.message.content));
                                    strcat(receivedPacket.message.content, replyContent);
                                    strcat(receivedPacket.message.content, "\n");
                                    strcat(receivedPacket.message.content, aux);
                                    
                                }
                                rc = sqlite3_prepare_v2(db, insertMessageQuery, -1, &insertMessageStmt, NULL);
                                handleDbError(rc, "Failed to prepare SQL statement for message insertion");
                                strcpy(receivedPacket.message.sender, connectionList[connectionIndex].username);
                                rc = sqlite3_bind_text(insertMessageStmt, 1, receivedPacket.message.sender, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind sender parameter for message insertion");
                                rc = sqlite3_bind_text(insertMessageStmt, 2, receivedPacket.message.receiver, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind receiver parameter for message insertion");
                                rc = sqlite3_bind_text(insertMessageStmt, 3, receivedPacket.message.content, -1, SQLITE_STATIC);
                                handleDbError(rc, "Failed to bind content parameter for message insertion");
                                pthread_mutex_unlock(&connectionListMutex);
                                if (strcmp(receivedPacket.message.replyId, "") == 0)
                                {
                                    // Bind NULL for reply ID
                                    rc = sqlite3_bind_null(insertMessageStmt, 4);
                                }
                                else
                                {
                                    // Convert the reply ID to an integer and bind it
                                    rc = sqlite3_bind_int(insertMessageStmt, 4, atoi(receivedPacket.message.replyId));
                                }
                                handleDbError(rc, "Failed to bind reply ID parameter for message insertion");

                                rc = sqlite3_step(insertMessageStmt);
                                if (rc == SQLITE_DONE)
                                {
                                    // The SQL statement has executed successfully

                                    // Get the last inserted row ID (message ID)
                                    int messageId = sqlite3_last_insert_rowid(db);

                                    // Convert the integer to a string and copy it to the receivedPacket.message.id field
                                    sprintf(receivedPacket.message.id, "%d", messageId);
                                    printf("inserted: %s\n", receivedPacket.message.id);
                                    pthread_mutex_lock(&connectionListMutex);
                                    // If the receiver is currently connected, send the message via a Packet
                                    int found = -1;
                                    for (int j = 0; j < MAX_CLIENTS; j++)
                                    {
                                        if (strcmp(connectionList[j].username, receivedPacket.message.receiver) == 0 && strcmp(connectionList[j].viewingConvo, connectionList[connectionIndex].username) == 0)
                                        {
                                            found = j;
                                            break;
                                        }
                                    }

                                    Packet destPacket;
                                    destPacket.type = MESSAGE_NOTIFICATION;
                                    strcpy(destPacket.message.id, receivedPacket.message.id);
                                    strcpy(destPacket.message.sender, connectionList[connectionIndex].username);
                                    strcpy(destPacket.message.receiver, receivedPacket.message.receiver);
                                    strcpy(destPacket.message.content, receivedPacket.message.content);

                                    const char *getTimeQuery = "SELECT CURRENT_TIMESTAMP FROM Messages;";
                                    sqlite3_stmt *getTimeStmt;

                                    rc = sqlite3_prepare_v2(db, getTimeQuery, -1, &getTimeStmt, NULL);
                                    handleDbError(rc, "Failed to prepare SQL statement for getting current timestamp");

                                    // Execute the query to get the current timestamp
                                    rc = sqlite3_step(getTimeStmt);

                                    // Check if the query was successful
                                    if (rc == SQLITE_ROW)
                                    {
                                        // Retrieve the timestamp from the result
                                        const char *currentTimestamp = (const char *)sqlite3_column_text(getTimeStmt, 0);

                                        // Now, 'currentTimestamp' contains the current timestamp
                                        printf("Current Timestamp: %s\n", currentTimestamp);
                                        strcpy(destPacket.message.timeStamp, currentTimestamp);
                                        unsigned char buffer[sizeof(Packet)];
                                        serializePacket(&destPacket, buffer, sizeof(buffer));
                                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                                        send(clientSocket, buffer, sizeof(buffer), 0);
                                        // You can store 'currentTimestamp' in a variable or use it as needed
                                    }
                                    else
                                    {
                                        // Handle the case where the query did not return a row
                                        printf("Failed to retrieve current timestamp.\n");
                                    }

                                    // Finalize the statement
                                    sqlite3_finalize(getTimeStmt);
                                    
                                    if (found != -1)
                                    {
                                        // send(connectionList[found].sd, &destPacket, sizeof(Packet), 0);
                                        unsigned char buffer[sizeof(Packet)];
                                        serializePacket(&destPacket, buffer, sizeof(buffer));
                                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                                        send(connectionList[found].sd, buffer, sizeof(buffer), 0);
                                    }
                                    pthread_mutex_unlock(&connectionListMutex);
                                    // Send SEND_MESSAGE_RESPONSE SUCCESS
                                    Packet responsePacket;
                                    responsePacket.type = SEND_MESSAGE_RESPONSE;
                                    responsePacket.error = SUCCESS;
                                    unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                                }
                                else
                                {
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
                    pthread_mutex_lock(&connectionListMutex);
                    // Check if the sender is logged in
                    if (strcmp(connectionList[connectionIndex].username, "") == 0)
                    {
                        Packet responsePacket;
                        responsePacket.type = VIEW_ALL_CONVOS_RESPONSE;
                        responsePacket.error = NOT_LOGGED_IN;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        strcpy(connectionList[connectionIndex].viewingConvo, "");
                        connectionList[connectionIndex].currentView = MAIN_VIEW;
                        // Select all unique participants where the current user is either the sender or receiver
                        const char *selectParticipantsQuery = "SELECT DISTINCT participant FROM ("
                                                            "    SELECT sender AS participant FROM Messages WHERE receiver = ?"
                                                            "    UNION"
                                                            "    SELECT receiver AS participant FROM Messages WHERE sender = ?"
                                                            ");";
                        sqlite3_stmt *selectParticipantsStmt;

                        int rc = sqlite3_prepare_v2(db, selectParticipantsQuery, -1, &selectParticipantsStmt, NULL);
                        handleDbError(rc, "Failed to prepare SQL statement for selecting participants");

                        rc = sqlite3_bind_text(selectParticipantsStmt, 1, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind username parameter for selecting participants");

                        rc = sqlite3_bind_text(selectParticipantsStmt, 2, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind username parameter for selecting participants");

                        // Iterate over the results and send each participant through VIEW_ALL_CONVOS_RESPONSE packet
                        while ((rc = sqlite3_step(selectParticipantsStmt)) == SQLITE_ROW)
                        {
                            const char *participant = (const char *)sqlite3_column_text(selectParticipantsStmt, 0);

                            Packet responsePacket;
                            responsePacket.type = VIEW_ALL_CONVOS_RESPONSE;
                            strcpy(responsePacket.user.username, participant);
                            unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                        }

                        sqlite3_finalize(selectParticipantsStmt);
                    }
                    pthread_mutex_unlock(&connectionListMutex);
                    break;
                }
                case VIEW_CONVERSATION: {
                    printf("view_convo received!\n");
                    pthread_mutex_lock(&connectionListMutex);
                    // Check if the user is logged in
                    if (strcmp(connectionList[connectionIndex].username, "") == 0)
                    {
                        Packet responsePacket;
                        responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                        responsePacket.error = NOT_LOGGED_IN;
                        unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                    }
                    else
                    {
                        // Check if the provided username is in the Users table
                        const char *checkUserQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
                        sqlite3_stmt *checkUserStmt;

                        int rc = sqlite3_prepare_v2(db, checkUserQuery, -1, &checkUserStmt, NULL);
                        handleDbError(rc, "Failed to prepare SQL statement for checking user existence");

                        rc = sqlite3_bind_text(checkUserStmt, 1, receivedPacket.user.username, -1, SQLITE_STATIC);
                        handleDbError(rc, "Failed to bind username parameter for checking user existence");

                        int userCount = 0;
                        rc = sqlite3_step(checkUserStmt);
                        if (rc == SQLITE_ROW)
                        {
                            userCount = sqlite3_column_int(checkUserStmt, 0);
                        }
                        sqlite3_finalize(checkUserStmt);

                        // If the provided username does not exist, send VIEW_CONVERSATION_RESPONSE INVALID_USER_DATA
                        if (userCount == 0)
                        {
                            Packet responsePacket;
                            responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                            responsePacket.error = INVALID_USER_DATA;
                            unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                        }
                        else
                        {
                            connectionList[connectionIndex].currentView = CONVERSATION_VIEW;
                            strcpy(connectionList[connectionIndex].viewingConvo, receivedPacket.user.username);
                            // Retrieve all messages exchanged between the two users
                            const char *selectMessagesQuery = "SELECT id, sender, receiver, content, timeStamp FROM Messages WHERE "
                                                            "(sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY timeStamp;";
                            sqlite3_stmt *selectMessagesStmt;

                            rc = sqlite3_prepare_v2(db, selectMessagesQuery, -1, &selectMessagesStmt, NULL);
                            handleDbError(rc, "Failed to prepare SQL statement for selecting messages");

                            rc = sqlite3_bind_text(selectMessagesStmt, 1, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind sender parameter for selecting messages");

                            rc = sqlite3_bind_text(selectMessagesStmt, 2, receivedPacket.user.username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind receiver parameter for selecting messages");

                            rc = sqlite3_bind_text(selectMessagesStmt, 3, receivedPacket.user.username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind sender parameter for selecting messages");

                            rc = sqlite3_bind_text(selectMessagesStmt, 4, connectionList[connectionIndex].username, -1, SQLITE_STATIC);
                            handleDbError(rc, "Failed to bind receiver parameter for selecting messages");

                            // Iterate over the results and send each message through VIEW_CONVERSATION_RESPONSE packet
                            while ((rc = sqlite3_step(selectMessagesStmt)) == SQLITE_ROW)
                            {
                                const char *id = (const char *)sqlite3_column_text(selectMessagesStmt, 0);
                                const char *sender = (const char *)sqlite3_column_text(selectMessagesStmt, 1);
                                const char *receiver = (const char *)sqlite3_column_text(selectMessagesStmt, 2);
                                const char *content = (const char *)sqlite3_column_text(selectMessagesStmt, 3);
                                const char *timeStamp = (const char *)sqlite3_column_text(selectMessagesStmt, 4);

                                Packet responsePacket;
                                responsePacket.type = VIEW_CONVERSATION_RESPONSE;
                                responsePacket.error = SUCCESS;
                                strcpy(responsePacket.message.id, id);
                                strcpy(responsePacket.message.sender, sender);
                                strcpy(responsePacket.message.receiver, receiver);
                                strcpy(responsePacket.message.content, content);
                                strcpy(responsePacket.message.timeStamp, timeStamp);

                                unsigned char buffer[sizeof(Packet)];
                        serializePacket(&responsePacket, buffer, sizeof(buffer));
                        xorEncryptDecrypt(buffer, sizeof(buffer), key);
                        send(clientSocket, buffer, sizeof(buffer), 0);
                            }

                            sqlite3_finalize(selectMessagesStmt);
                        }
                    }
                    pthread_mutex_unlock(&connectionListMutex);
                    break;
                }
                default: {
                    Packet P2;
                    P2.type = EMPTY;
                    P2.error = SUCCESS;
                    unsigned char buffer[sizeof(Packet)];
                    serializePacket(&P2, buffer, sizeof(buffer));
                    xorEncryptDecrypt(buffer, sizeof(buffer), key);
                    send(clientSocket, buffer, sizeof(buffer), 0);
                    // send(clientSocket, &P2, sizeof(Packet), 0);
                }
            }
        } else if (bytesReceived <= 0) {
            // client closed connection
            pthread_mutex_lock(&connectionListMutex);
            printf("client from index [%d] = %d (%s) disconnected!\n",connectionIndex, connectionList[connectionIndex].sd, connectionList[connectionIndex].username);
            close(clientSocket);
            connectionList[connectionIndex].sd = -1;
            strcpy(connectionList[connectionIndex].username, "");
            pthread_mutex_unlock(&connectionListMutex);
            pthread_exit(NULL);
        }
    }

    close(clientSocket);
    pthread_exit(NULL);
}

int main() {
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
        perror("bind error");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    if (listen(serverSocket, 5) == -1) {
        perror("listen error");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    while(1) {
        struct sockaddr_in clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);

        if (clientSocket == -1) {
            perror("accept error");
            continue;
        }
        pthread_mutex_lock(&connectionListMutex);
        int connectionIndex;
        for(connectionIndex = 0; connectionIndex < MAX_CLIENTS; connectionIndex++) {
            if(connectionList[connectionIndex].sd == -1) {
                connectionList[connectionIndex].sd = clientSocket;
                break;
            }
        }
        pthread_mutex_unlock(&connectionListMutex);
        if (connectionIndex == MAX_CLIENTS) {
            // No available slot in connectionList
            close(clientSocket);
            continue;
        }
        int* args = (int*)malloc(2 * sizeof(int));
        args[0] = clientSocket;
        args[1] = connectionIndex;
        pthread_t threadId;
        if(pthread_create(&threadId, NULL, clientHandler, args) != 0) {
            perror("pthread_create error");
            close(clientSocket);
        }
        pthread_detach(threadId);
    }

    close(serverSocket);
    return 0;
}
