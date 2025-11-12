#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <dirent.h>
#include <string>
#include <sstream>
#include <fstream>

#define PORT 8080
#define KEY 0x5A   

std::string xorEncryptDecrypt(const std::string &data) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i)
        result[i] = data[i] ^ KEY;
    return result;
}

std::string listFiles(const std::string &path) {
    DIR *dir;
    struct dirent *entry;
    std::stringstream files;
    dir = opendir(path.c_str());
    if (!dir) return "Failed to open directory.\n";

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_REG)
            files << entry->d_name << "\n";
    }
    closedir(dir);
    return files.str();
}

std::string readFileContent(const std::string &filename) {
    std::ifstream file("server/server_files/" + filename, std::ios::binary);
    if (!file.is_open()) return "ERROR: File not found";
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

bool authenticate(int socket) {
    char buffer[1024] = {0};
    read(socket, buffer, sizeof(buffer));

    std::string credentials(buffer);
    std::ifstream file("server/users.txt");
    if (!file.is_open()) {
        std::string msg = xorEncryptDecrypt("ERROR: User file not found");
        send(socket, msg.c_str(), msg.size(), 0);
        return false;
    }

    std::string line;
    bool valid = false;
    while (std::getline(file, line)) {
        if (line == credentials) {
            valid = true;
            break;
        }
    }
    file.close();

    if (valid) {
        std::string msg = xorEncryptDecrypt("AUTH_SUCCESS");
        send(socket, msg.c_str(), msg.size(), 0);
        return true;
    } else {
        std::string msg = xorEncryptDecrypt("AUTH_FAIL");
        send(socket, msg.c_str(), msg.size(), 0);
        return false;
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[4096] = {0};

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket failed");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);

    std::cout << "✅ Server ready. Waiting for clients...\n";

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        if (new_socket < 0) {
            perror("Accept failed");
            continue;
        }

        std::cout << "👋 Client connected.\n";

        if (!authenticate(new_socket)) {
            std::cout << "❌ Authentication failed. Closing connection.\n";
            close(new_socket);
            continue;
        }
        std::cout << "🔐 Client authenticated successfully.\n";

        memset(buffer, 0, sizeof(buffer));
        read(new_socket, buffer, 1024);
        std::string command = xorEncryptDecrypt(std::string(buffer));

        if (command == "LIST") {
            std::string files = listFiles("server/server_files");
            std::string enc = xorEncryptDecrypt(files);
            send(new_socket, enc.c_str(), enc.size(), 0);
            std::cout << "📁 Sent encrypted file list.\n";
        }
        else if (command.rfind("GET ", 0) == 0) {
            std::string filename = command.substr(4);
            std::string content = readFileContent(filename);
            std::string enc = xorEncryptDecrypt(content);
            send(new_socket, enc.c_str(), enc.size(), 0);
            std::cout << "📦 Sent encrypted file '" << filename << "'.\n";
        }
        else if (command.rfind("PUT ", 0) == 0) {
            std::string filename = command.substr(4);
            std::cout << "⬆️ Receiving file (encrypted): " << filename << "\n";

            std::string ready = xorEncryptDecrypt("READY");
            send(new_socket, ready.c_str(), ready.size(), 0);

            std::ofstream outfile("server/server_files/" + filename, std::ios::binary);
            int bytesReceived;
            while ((bytesReceived = read(new_socket, buffer, sizeof(buffer))) > 0) {
                std::string chunk(buffer, bytesReceived);
                std::string decrypted = xorEncryptDecrypt(chunk);
                outfile.write(decrypted.c_str(), decrypted.size());
            }
            outfile.close();
            std::cout << "✅ File '" << filename << "' uploaded and decrypted successfully.\n";
        }
        else {
            std::string msg = xorEncryptDecrypt("Unknown command.\n");
            send(new_socket, msg.c_str(), msg.size(), 0);
        }

        close(new_socket);
    }

    close(server_fd);
    return 0;
}
