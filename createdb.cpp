#include <iostream>
#include <sqlite3.h>

int main() {
    sqlite3* db;
    char* errorMessage = nullptr;

    int rc = sqlite3_open("database.db", &db);

    if (rc != SQLITE_OK) {
        std::cerr << "error: cannot open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return rc;
    }

    std::cout << "database 'database.db' opened successfully." << std::endl;

    // Execute SQL commands to create tables
    const char* createUsersTable = "CREATE TABLE Users ("
                                "    username VARCHAR PRIMARY KEY,"
                                "    password VARCHAR NOT NULL"
                                ");";

    const char* createMessagesTable = "CREATE TABLE Messages ("
                                        "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
                                        "    sender VARCHAR NOT NULL,"
                                        "    receiver VARCHAR NOT NULL,"
                                        "    content VARCHAR NOT NULL,"
                                        "    timeStamp DATETIME NOT NULL,"
                                        "    replyId INTEGER,"
                                        "    isDeleted BOOLEAN NOT NULL,"
                                        "    FOREIGN KEY (sender) REFERENCES Users(username),"
                                        "    FOREIGN KEY (receiver) REFERENCES Users(username),"
                                        "    FOREIGN KEY (replyId) REFERENCES Messages(id)"
                                        ");";


    // USERS
    rc = sqlite3_exec(db, createUsersTable, nullptr, nullptr, &errorMessage);
    if (rc != SQLITE_OK) {
        std::cerr << "error creating Users table: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        sqlite3_close(db);
        return rc;
    }


    // MESSAGES
    rc = sqlite3_exec(db, createMessagesTable, nullptr, nullptr, &errorMessage);
    if (rc != SQLITE_OK) {
        std::cerr << "error creating Messages table: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        sqlite3_close(db);
        return rc;
    }

    std::cout << "tables created successfully." << std::endl;

    sqlite3_close(db);

    std::cout << "database closed." << std::endl;

    return 0;
}
