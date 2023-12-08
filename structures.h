// GENERAL STRUCTURES USED BY BOTH CLIENT & SERVER

#define USERNAME_LENGTH 32
#define PASSWORD_LENGTH 32
#define ID_LENGTH 16
#define CONTENT_LENGTH 64

struct User {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH];
};

struct Message {
    char id[ID_LENGTH];
    char sender[USERNAME_LENGTH];
    char receiver[USERNAME_LENGTH];
    char content[CONTENT_LENGTH];
    char replyId[ID_LENGTH]; // optional, only if this message is replying to another one
};

enum PacketType {
    LOGIN, // server will analyze the User part of the Packet it receives from client
    LOGIN_RESPONSE,
    LOGOUT,
    LOGOUT_RESPONSE,
    SEND_MESSAGE,  // server will analyze the Message part of the Packet it receives from client
    SEND_MESSAGE_RESPONSE,
    VIEW_ALL_CONVOS,
    VIEW_ALL_CONVOS_RESPONSE,  // client will analyze the User part of the Packet it receives from server
    VIEW_CONVERSATION,
    VIEW_CONVERSATION_RESPONSE // client will analyze the Message part of the Packet it receives from server
};

enum ErrorType {
    SUCCESS,
    INVALID_USER_DATA, // inexistent user or wrong password
    NOT_LOGGED_IN, // when user tries to send message or log out, but it is not logged in the first place
    NOT_LOGGED_OUT, // when user tries to login, but they are already logged in
    INVALID_REPLY_ID // for when the user tries to respond to an inexistent message
};

struct Packet {
    PacketType type;
    ErrorType error;
    User user;
    Message message;
};

// STRUCTURES USED BY SERVER
struct Connection {
    int sd;
    char username[USERNAME_LENGTH];
}; // server will manage an array of type Connection through which it will know how many clients are connected and with what users