#include <iostream>
#include <cstdlib>

int main() {
    const char* databaseFile = "database.db";

    if (std::remove(databaseFile) == 0) {
        std::cout << "database file '" << databaseFile << "' removed successfully." << std::endl;
    } else {
        std::cerr << "error: Unable to remove database file '" << databaseFile << "'." << std::endl;
    }

    return 0;
}
