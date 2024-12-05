#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <string>
#include <array>
#include "protocol.h"


/**
 *  This struct is used to store the information read from the transfer.info file.
 *  It contains the IP, port, name, and path of the file to transfer.
 *
 * Members:
 * 	 ip: The IP address of the server.
 * 	 port: The port number of the server.
 * 	 name: The name of the client.
 *   path: The path of the file to transfer.
 */
struct transfer_info_data {
	std::string ip;
	std::string port;
	std::string name;
	std::string path;
};


/**
 *  This struct is used to store the information read from the me.info file.
 *  It contains the name, client ID, and base64 private key of the client.
 *
 * Members:
 * 	 name: The name of the client.
 * 	 client_id: The client ID of the client.
 *   base64_private_key: The base64 encoded private key of the client.
 */
struct user_info_data {
	std::string name;
	std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE> client_id;
	std::string base64_private_key;
};


/**
 * This function checks if a file exists at the specified path.
 *
 * Parameters:
 *       path: The path of the file to check.
 *
 * Return:
 *       true if the file exists, false otherwise.
 */
bool is_exist_file(const std::string& path);
/**
 * This function reads the transfer.info file and stores the information in the transfer_info_data struct.
 * The file should contain the IP and port, client name, and file path in separate lines.
 *
 * The function throws a runtime_error if the file does not exist, could not be opened, or if the format is invalid.
 *
 *
 * Parameters:
 *     data: The transfer_info_data struct to store the information read from the file.
 *
 */
void load_transfer_info(transfer_info_data& data);
/**
 * This function reads the me.info file and stores the information in the user_info_data struct.
 * The file should contain the name, client ID, and base64 private key in separate lines.
 *
 * The function throws a runtime_error if the file does not exist, could not be opened, or if the format is invalid.
 *
 *
 * Parameters:
 *     data: The user_info_data struct to store the information read from the file.
 *
 */
void load_user_info(user_info_data& data);
/**
 * This function creates a file named me.info and writes the client's name, client ID, and base64 private key to it.
 * The client ID is written as a hex string.
 *
 * Parameters:
 *    data: The user_info_data struct containing the client's name, client ID, and base64 private key.
 *
 */
void create_user_info_file(const user_info_data& data);
/**
 * This function creates a file named private_key.pem and writes the base64 private key to it.
 * 
 * Parameters:
 *     base64_private_key: The base64 encoded private key to write to the file.
 *
 */
void create_private_key_file(const std::string& base64_private_key);
/**
 * The function extracts the file name from the given path.
 *
 * Parameters:
 *     path: The path to extract the file name from.
 *
 * Returns:
 *     The file name extracted from the path.
 *
 */
std::string extract_file_name_from_path(const std::string& path);
/**
 * This function returns the size of the file that is located at the specified path.
 *
 * Parameters:
 *     filePath: The path of the file to get the size of.
 *
 * Returns:
 *     The size of the file.
 */
size_t get_file_size(const std::string& filePath);
/**
 * This function reads the content of the file at the specified path from the given position
 * until the specified size and returns the content between the specified position and size.
 *
 * Parameters:
 *      file_path: The path of the file to read.
 *	    pos: The position to start reading from.
 *      size: The size of the content to read.
 *
 * Returns:
 *     The content of the file.
 */
std::string read_file_content(const std::string& file_path, size_t pos, size_t size);

#endif