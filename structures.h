#include <cstring>

// GENERAL STRUCTURES USED BY BOTH CLIENT & SERVER

#define USERNAME_LENGTH 32
#define PASSWORD_LENGTH 32
#define ID_LENGTH 16
#define CONTENT_LENGTH 64
#define TIMESTAMP_LENGTH 32

struct User {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
};

struct Message {
    char id[ID_LENGTH];
    char sender[USERNAME_LENGTH];
    char receiver[USERNAME_LENGTH];
    char content[CONTENT_LENGTH];
    char timeStamp[TIMESTAMP_LENGTH];
    char replyId[ID_LENGTH]; // optional, only if this message is replying to another one
};

enum PacketType {
    EMPTY,
    REGISTER,
    REGISTER_RESPONSE,
    LOGIN, // server will analyze the User part of the Packet it receives from client
    LOGIN_RESPONSE,
    LOGOUT,
    LOGOUT_RESPONSE,
    SEND_MESSAGE,  // server will analyze the Message part of the Packet it receives from client
    SEND_MESSAGE_RESPONSE,
    MESSAGE_NOTIFICATION,
    VIEW_ALL_CONVOS,
    VIEW_ALL_CONVOS_RESPONSE,  // client will analyze the User part of the Packet it receives from server
    VIEW_CONVERSATION,
    VIEW_CONVERSATION_RESPONSE // client will analyze the Message part of the Packet it receives from server
};

enum ErrorType {
    SUCCESS,
    USER_ALREADY_EXISTS,
    INVALID_USER_DATA, // inexistent user or wrong password
    USER_ALREADY_CONNECTED,
    NOT_LOGGED_IN, // when user tries to send message or log out, but it is not logged in the first place
    NOT_LOGGED_OUT, // when user tries to login, but they are already logged in
    INVALID_REPLY_ID, // for when the user tries to respond to an inexistent message
    WRONG_VIEW
};

struct Packet {
    PacketType type;
    ErrorType error;
    User user;
    Message message;
};

enum ViewType {
    LOGIN_VIEW,
    MAIN_VIEW,
    CONVERSATION_VIEW
};

// STRUCTURES USED BY SERVER
struct Connection {
    int sd;
    char username[USERNAME_LENGTH];
    ViewType currentView;
    char viewingConvo[USERNAME_LENGTH];
}; // server will manage an array of type Connection through which it will know how many clients are connected and with what users

void serializePacket(const Packet *packet, unsigned char *buffer, size_t bufferSize) {
    if (bufferSize < sizeof(Packet)) {
        // Handle error: buffer too small
        return;
    }
    memcpy(buffer, packet, sizeof(Packet));
}

void deserializePacket(const unsigned char *buffer, Packet *packet) {
    memcpy(packet, buffer, sizeof(Packet));
}

const char *key = "tenacity"; // should be the same on both client and server

void xorEncryptDecrypt(unsigned char *data, int data_len, const char* key) {
    size_t key_len = strlen(key);
    for (size_t i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}