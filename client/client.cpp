#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <fstream>

#define PORT 8080
#define KEY 0x5A   // Same key as server

// ---------- XOR Encrypt/Decrypt ----------
std::string xorEncryptDecrypt(const std::string &data) {
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i)
        result[i] = data[i] ^ KEY;
    return result;
}

// ---------- File Download ----------
void downloadFile(const std::string &filename) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // Authenticate
    std::string user = "admin";
    std::string pass = "1234";
    std::string creds = user + ":" + pass;
    send(sock, creds.c_str(), creds.size(), 0);

    char auth_response[1024] = {0};
    read(sock, auth_response, sizeof(auth_response));
    std::string dec_auth = xorEncryptDecrypt(std::string(auth_response));
    if (dec_auth != "AUTH_SUCCESS") {
        std::cout << "❌ Authentication failed.\n";
        close(sock);
        return;
    }

    // Request file
    std::string command = xorEncryptDecrypt("GET " + filename);
    send(sock, command.c_str(), command.size(), 0);
    std::cout << "📥 Requesting file: " << filename << "\n";

    std::ofstream outfile("client/client_downloads/" + filename, std::ios::binary);
    char buffer[4096];
    int bytesReceived;
    while ((bytesReceived = read(sock, buffer, sizeof(buffer))) > 0) {
        std::string chunk(buffer, bytesReceived);
        std::string decrypted = xorEncryptDecrypt(chunk);
        outfile.write(decrypted.c_str(), decrypted.size());
    }
    outfile.close();
    std::cout << "✅ File '" << filename << "' downloaded and decrypted successfully.\n";

    close(sock);
}

// ---------- File Upload ----------
void uploadFile(const std::string &filename) {
    std::ifstream infile("client/" + filename, std::ios::binary);
    if (!infile.is_open()) {
        std::cout << "❌ File not found: " << filename << "\n";
        return;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // Authenticate
    std::string user = "admin";
    std::string pass = "1234";
    std::string creds = user + ":" + pass;
    send(sock, creds.c_str(), creds.size(), 0);
    char auth_response[1024] = {0};
    read(sock, auth_response, sizeof(auth_response));
    std::string dec_auth = xorEncryptDecrypt(std::string(auth_response));
    if (dec_auth != "AUTH_SUCCESS") {
        std::cout << "❌ Authentication failed.\n";
        close(sock);
        return;
    }

    // Send command
    std::string command = xorEncryptDecrypt("PUT " + filename);
    send(sock, command.c_str(), command.size(), 0);

    // Wait for READY
    char ack[16] = {0};
    read(sock, ack, sizeof(ack));
    std::string ready = xorEncryptDecrypt(std::string(ack));
    if (ready != "READY") {
        std::cout << "⚠️ Server not ready.\n";
        close(sock);
        return;
    }

    // Send encrypted file
    char buffer[4096];
    while (infile.read(buffer, sizeof(buffer)) || infile.gcount() > 0) {
        std::string chunk(buffer, infile.gcount());
        std::string encrypted = xorEncryptDecrypt(chunk);
        send(sock, encrypted.c_str(), encrypted.size(), 0);
    }

    infile.close();
    close(sock);
    std::cout << "⬆️ File '" << filename << "' encrypted and uploaded successfully.\n";
}

// ---------- Main ----------
int main() {
    while (true) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(PORT);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
        connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

        // Authenticate
        std::string user = "admin";
        std::string pass = "1234";
        std::string creds = user + ":" + pass;
        send(sock, creds.c_str(), creds.size(), 0);
        char auth_response[1024] = {0};
        read(sock, auth_response, sizeof(auth_response));
        std::string dec_auth = xorEncryptDecrypt(std::string(auth_response));
        if (dec_auth != "AUTH_SUCCESS") {
            std::cout << "❌ Authentication failed.\n";
            close(sock);
            return 0;
        }
        std::cout << "✅ Authenticated successfully!\n";

        // Request file list
        std::string command = xorEncryptDecrypt("LIST");
        send(sock, command.c_str(), command.size(), 0);
        char buffer[4096] = {0};
        int bytes = read(sock, buffer, sizeof(buffer));
        std::string decrypted = xorEncryptDecrypt(std::string(buffer, bytes));
        std::cout << "📄 Files on server:\n" << decrypted << "\n";
        close(sock);

        // Menu
        int choice;
        std::cout << "\n1️⃣ Download file\n2️⃣ Upload file\n3️⃣ Exit\nEnter choice: ";
        std::cin >> choice;

        if (choice == 1) {
            std::string filename;
            std::cout << "Enter filename to download: ";
            std::cin >> filename;
            downloadFile(filename);
        } else if (choice == 2) {
            std::string filename;
            std::cout << "Enter filename to upload (place it inside 'client/' folder): ";
            std::cin >> filename;
            uploadFile(filename);
        } else if (choice == 3) {
            std::cout << "👋 Exiting client. Goodbye!\n";
            break;
        } else {
            std::cout << "Invalid choice.\n";
        }
    }

    return 0;
}
