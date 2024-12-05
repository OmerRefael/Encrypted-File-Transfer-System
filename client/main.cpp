/**
 * Main file of the client application.
 *
 * This application initializes and connects to the server, allowing users to
 * transfer encrypted files for storage.
 *
 * The client sends requests to the server using a specified protocol that we have implemented.
 * It can perform actions such as registering, reconnecting, and uploading files to the server.
 * Some details of the process are also saved in addition to the database file.
 *
 * @autor: Omer Refael
 * @data: 20/10/2024
*/


#include <string>
#include <array>
#include <stdexcept>
#include <memory>
#include "client.h"
#include "client_logic.h"
#include "file_handler.h"
#include "logger.h"

static Logger logger(__FILE__);

int main(int argc, char* argv[])
{
    try {
		transfer_info_data transfer_file_data;
		user_info_data user_file_data;

		bool is_fatal_error = false;

		load_transfer_info(transfer_file_data); // Load the transfer file data - ip, port, name, path
		Client client(transfer_file_data.ip, transfer_file_data.port); 
		if (is_exist_file("me.info")) { // Check if the file "me.info" exists
			load_user_info(user_file_data); // Load the user file data - name, client_id, base64_private_key
			ClientLogic::handle_reconnect_process(client, std::make_unique<transfer_info_data>(transfer_file_data),
				std::make_unique<user_info_data>(user_file_data),&is_fatal_error);
        }
        else {
			ClientLogic::handle_register_process(client, std::make_unique<transfer_info_data>(transfer_file_data),
				std::make_unique<user_info_data>(user_file_data), &is_fatal_error);
        }
    }
	catch (const std::exception& e) {
		logger.log(Logger::Level::PROBLEM, e.what(), __LINE__);
	}   
    return 0;
}