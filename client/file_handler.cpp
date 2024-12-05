#include <string>
#include <cstdint>
#include <stdexcept>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>
#include <array>
#include "file_handler.h"
#include "utils/bytes_utils.h"

#define MAX_LENGTH_OF_NAME 100


/**
 * This function get a line (from transfer.info) and parse it to get the IP and port of the server.
 * 
 * Parameters:
 *     line: The line to parse.
 *     data: The transfer_info_data struct to store the IP and port.
 */
void parse_server_info(const std::string& line, transfer_info_data& data);
/**
 * This function get a line (from transfer.info) and parse it to get the client name.
 * 
 * Parameters:
 *     line: The line to parse.
 *     client_name: The string to store the client name.
 */
void parse_client_name(const std::string& line, std::string& client_name);
/**
 * This function get a line (from me.info) and parse it to get the client ID.
 * 
 * Parameters:
 *     line: The line to parse.
 *     client_id: The array to store the client ID.
 */
void parse_client_id(const std::string& line, std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id);
/**
 * This function reads the base64 private key from the me.info file.
 * 
 * Parameters:
 *     base64_private_key: The string to store the base64 private key.
 */
void parse_base64_private_key(std::string& base64_private_key);


bool is_exist_file(const std::string& path) {
    std::ifstream file(path); // Try to open the file
    return file.good();  // Check if the file opened successfully
}


void load_transfer_info(transfer_info_data& data) {
    if (!is_exist_file("transfer.info")) {
        throw std::runtime_error("transfer.info file does not exist.");
    }

    std::ifstream file("transfer.info");
    if (!file.is_open()) {
        throw std::runtime_error("Could not open transfer.info file.");
    }

    std::string line;

    // Read the first line for IP and port
    std::getline(file, line);
    parse_server_info(line, data);

    // Read the second line for client name
    std::getline(file, line);
    parse_client_name(line, data.name);

    // Read the third line for file path
    std::getline(file, line);
    if (line.empty()) {
        throw std::runtime_error("Missing file path in transfer.info.");
    }
    data.path = line; 

	if (std::getline(file, line)) {throw std::runtime_error("Extra lines in transfer.info.");}

    file.close();
}


void load_user_info(user_info_data& data) {
    std::ifstream file("me.info");

    // Check if the file opened successfully
    if (!file.is_open()) {
        throw std::runtime_error("Could not open me.info file.");
    }

    std::string line;

    // Read the first line for the name
    std::getline(file, line);
    parse_client_name(line, data.name);

    // Read the second line for the unique client ID
    std::getline(file, line);
    parse_client_id(line, data.client_id);

    // Read the remaining lines for the base64 private key
    parse_base64_private_key(data.base64_private_key);

    file.close(); // Close the file after reading
}


void parse_server_info(const std::string& line, transfer_info_data& data) {
    if (line.empty()) {
        throw std::runtime_error("Missing IP and port in transfer.info.");
    }

    const std::string white_spaces = " \t\r\f\v";
	if (line.find_first_of(white_spaces) != std::string::npos) {
		throw std::runtime_error("Avoid using spaces in the IP and port line of transfer.info.");
	}


    std::size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos) {
        throw std::runtime_error("Invalid format for IP and port in transfer.info.");
    }
    data.ip = line.substr(0, colon_pos);
    data.port = line.substr(colon_pos + 1);
}


void parse_client_name(const std::string& line, std::string& client_name) {
    if (line.empty()) {
        throw std::runtime_error("Missing client name in the file.");
    }

    if (line.length() > MAX_LENGTH_OF_NAME) {
        throw std::runtime_error("Client name exceeds 100 characters.");
    }
    client_name = line;
}


void parse_client_id(const std::string& line, std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id) {
    if (line.empty()) {
        throw std::runtime_error("Missing client ID in the file.");
    }

    if (line.length() != RequestHeader::CLIENT_ID_SIZE * 2) {
        throw std::runtime_error("Invalid client ID length in me.info.");
    }

    // Convert hex string to byte array
    auto unhexed_id = unhexed(line);
    std::copy(unhexed_id.begin(), unhexed_id.end(), client_id.begin());
}


void parse_base64_private_key(std::string& base64_private_key) {
    std::ifstream file("priv.key");

    // Check if the file was opened successfully
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open priv.key.");
    }

    std::string line;
    while (std::getline(file, line)) {
        base64_private_key += line;
    }

	// Check if the base64 private key was read successfully from the file and it is not empty
    if (base64_private_key.empty()) {
        throw std::runtime_error("Failed to read base64 private key from me.info.");
    }
}


void create_user_info_file(const user_info_data& data) {
    std::ofstream file("me.info");

    // Check if the file opened successfully
    if (!file.is_open()) {
        throw std::runtime_error("Could not open me.info file for storing the information about the registration process of the client.");
    }

    // Write the name to the file
    file << data.name << std::endl;

    // Write the client ID to the file as a hex string
    file << hexify(data.client_id.data(), data.client_id.size()) << std::endl;

    // Write the base64 private key to the file
    file << data.base64_private_key;
}


void create_private_key_file(const std::string& base64_private_key) {
	std::ofstream file("priv.key");

	// Check if the file opened successfully
	if (!file.is_open()) {
		throw std::runtime_error("Could not open priv.key file for storing the base64 private key of the client.");
	}

	// Write the base64 private key to the file
	file << base64_private_key;
}


std::string extract_file_name_from_path(const std::string& path) {
    std::filesystem::path fs_path(path);
    return fs_path.filename().string();
}


size_t get_file_size(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary);
	if (!file.is_open()) {
		throw std::runtime_error("Could not open file: " + filePath);
	}

	file.seekg(0, std::ios::end); // Move the file pointer to the end of the file
	size_t size = file.tellg(); // Get the position of the file pointer
	file.seekg(0, std::ios::beg); // Move the file pointer back to the beginning of the file

	if (size == -1) {
		throw std::runtime_error("Failed to get the size of the file: " + filePath);
	}
   
	return size;
}


std::string read_file_content(const std::string& file_path, size_t pos, size_t size) {
    std::ifstream file(file_path, std::ios::binary);
    // Check if the file opened successfully
	if (!file) { 
		throw std::runtime_error("Could not open file: " + file_path);
    }

    // Check if the position is valid
    if (file.eof()) {
        throw std::runtime_error("Position exceeds file size: " + file_path);
    }

	file.seekg(pos); // Move the file pointer to the specified position
	std::vector<char> buffer(size); // Create a buffer to store the file content
	file.read(buffer.data(), size); // Read the specified number of bytes from the file

	if (!file) {
		throw std::runtime_error("Failed to read file content: " + file_path);
	}

	return std::string(buffer.begin(), buffer.end()); // Return the content as a string
}
