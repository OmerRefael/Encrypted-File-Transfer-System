#include <string>
#include <cstdint>
#include <vector>
#include <array>
#include <set>
#include "client_logic.h"
#include "client.h"
#include "protocol.h"
#include "file_handler.h"
#include "cksum.h"
#include "logger.h"
#include "utils/encryption_utils.h"
#include "utils/general_utils.h"


#define AMOUNT_OF_TRIES 3
#define INVALUD_CRC_IN_THE_FOURTH_TIME 4


static Logger logger(__FILE__);


void ClientLogic::handle_reconnect_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error) {
    auto [header_response, payload_response] = handle_reconnect_request(client, user_file_data->name, user_file_data->client_id, is_fatal_error); // Send the reconnect request
    if (*is_fatal_error) return; // Check if a fatal error occurred

    if (header_response.get_code() == ResponseCode::RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY) { // Reconnect request accepted
        handle_reconnect_accepted_process(payload_response, std::move(user_file_data), std::move(transfer_file_data), client, is_fatal_error);
    }
    else { // Reconnect request rejected
        handle_reconnect_rejected_process(client, std::move(transfer_file_data), std::move(user_file_data), is_fatal_error);
    }
}

void ClientLogic::handle_reconnect_accepted_process(const ResponsePayload& payload_response, std::unique_ptr<user_info_data> user_file_data, std::unique_ptr<transfer_info_data> transfer_file_data, Client& client, bool *is_fatal_error) {
    logger.log(Logger::Level::INFO, "Reconnect request accepted", __LINE__); // Log the accepted reconnect request
	std::string aes_key_encrypted = payload_response.get_payload_as<ReconnectRequestAcceptedPayload>().get_aes_encrypted_key(); // Get the encrypted AES key
    std::string aes_key = decrypt_data_by_private_key(user_file_data->base64_private_key, aes_key_encrypted); // Decrypt the AES key
    handle_send_file_progress(client, user_file_data->client_id, transfer_file_data->path, aes_key, is_fatal_error); // Send the required file
}

void ClientLogic::handle_reconnect_rejected_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error) {
    logger.log(Logger::Level::WARNING, "Reconnect request rejected", __LINE__); // Log the rejected reconnect request
    logger.log(Logger::Level::INFO, "Registration process will start now", __LINE__); // Log that the registration process will start now
    handle_register_process(client, std::move(transfer_file_data), std::move(user_file_data), is_fatal_error); // Start the registration process
}

void ClientLogic::handle_register_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error) {
    auto [header_response, payload_response] = handle_registration_request(client, transfer_file_data->name, is_fatal_error);
    if (*is_fatal_error) return; // Check if a fatal error occurred
 
    if (header_response.get_code() == ResponseCode::REGISTRATION_SUCCEEDED) { // Registration succeeded
        handle_registration_success(std::move(transfer_file_data), std::move(user_file_data), payload_response, client, is_fatal_error);
    }
    else { // Registration failed
        handle_registration_failure(); 
    }
}

void ClientLogic::handle_registration_success(std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, const ResponsePayload& payload_response, Client& client, bool *is_fatal_error) {
    user_file_data->name = transfer_file_data->name;
	user_file_data->client_id = payload_response.get_payload_as<RegisterSuccessedPayload>().get_client_id(); // Get the client ID
    logger.log(Logger::Level::INFO, "Registration succeeded", __LINE__);

    auto [header_response, payload_response_key] = handle_send_public_key_request(client, transfer_file_data->name, user_file_data->client_id, user_file_data->base64_private_key, is_fatal_error);
    if (*is_fatal_error) return; // Check if a fatal error occurred

    create_user_info_file(*user_file_data); // Create the me.info file
	create_private_key_file(user_file_data->base64_private_key); // Create the private key file

	std::string aes_key_encrypted = payload_response_key.get_payload_as<ReceivedEncryptedAesKeyPayload>().get_aes_encrypted_key();
    std::string aes_key = decrypt_data_by_private_key(user_file_data->base64_private_key, aes_key_encrypted);

    handle_send_file_progress(client, user_file_data->client_id, transfer_file_data->path, aes_key, is_fatal_error);
}

void ClientLogic::handle_registration_failure() { 
    logger.log(Logger::Level::WARNING, "Registration failed - try again with other details", __LINE__); // Log that the registration failed
}


std::pair<ResponseHeader, ResponsePayload> ClientLogic::handle_reconnect_request(Client& client, const std::string& name, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, bool *is_fatal_error) {
    const std::set<ResponseCode> reconnect_expected_response_codes = {
    ResponseCode::RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY,
    ResponseCode::RECONNECT_REQUEST_REJECTED
    }; // Set of expected response codes
   
    
    for (int counter_of_tries = 1; counter_of_tries <= AMOUNT_OF_TRIES; ++counter_of_tries) { // Loop through the amount of tries
		logger.log(Logger::Level::INFO, "Attempting to reconnect", __LINE__); // Log that the reconnect will be attempted

        // Create and send the reconnect request
        send_reconnect_request(client, client_id, name); // Send the reconnect request

        // Receive the response
        auto [response_header, response_payload] = receive_reconnect_response(client); // Receive the response

        // Check the response
		if (reconnect_expected_response_codes.find(response_header.get_code()) != reconnect_expected_response_codes.end()) { // Check if the response code is in the expected response codes
            return std::make_pair(response_header, response_payload);
        }

        logger.log(Logger::Level::WARNING, "Attempt to reconnect failed. Retrying...", __LINE__); // Log that the reconnect failed
    }

	handle_fatal_error("Reconnect request failed after multiple attempts, due to persistent errors in sending the reconnect request", __LINE__, is_fatal_error); // Handle a fatal
    return std::make_pair(ResponseHeader(), ResponsePayload()); // Return an empty pair
}

void ClientLogic::send_reconnect_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& name) {
    RequestCode code = RequestCode::RECONNECT;
    uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::RECONNECT_SIZE);

    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size); // Create the request header
    ReconnectPayload reconnect_payload(name);
    RequestPayload request_payload(code, payload_size, { reconnect_payload }); // Create the request payload

    client.send_header_request(request_header); // Send the header
    client.send_payload_request(request_payload); // Send the request
}

std::pair<ResponseHeader, ResponsePayload> ClientLogic::receive_reconnect_response(Client& client) {
    ResponseHeader response_header = client.receive_header_response();
    ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size());
    return { response_header, response_payload }; // Return the response pair
}

std::pair<ResponseHeader, ResponsePayload> ClientLogic::handle_registration_request(Client& client, const std::string& name, bool *is_fatal_error) {
    
    const std::set<ResponseCode> registration_expected_response_codes = {
        ResponseCode::REGISTRATION_SUCCEEDED,
        ResponseCode::REGISTRATION_FAILED
    }; // Set of expected response codes
    
    for (int counter_of_tries = 1; counter_of_tries <= AMOUNT_OF_TRIES; ++counter_of_tries) {
		logger.log(Logger::Level::INFO, "Attempting to register", __LINE__); // Log that the registration will be attempted
        // Create and send the registration request
        send_registration_request(client, name);

        // Receive the response
        auto [response_header, response_payload] = receive_registration_response(client);

        // Check the response
		if (registration_expected_response_codes.find(response_header.get_code()) != registration_expected_response_codes.end()) {
            return std::make_pair(response_header, response_payload);
        }

        logger.log(Logger::Level::WARNING, "Attempt to register failed. Retrying...", __LINE__); // Log that the registration failed
    }

	handle_fatal_error("Registration request failed after multiple attempts, due to persistent errors in sending the registration request", __LINE__, is_fatal_error); // Handle a fatal error
    return std::make_pair(ResponseHeader(), ResponsePayload());
}

void ClientLogic::send_registration_request(Client& client, const std::string& name) {
    std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE> client_id = {}; // Ignored, set to 0
    RequestCode code = RequestCode::REGISTRATION;
    uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::REGISTRATION_SIZE);

    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);
    RegisterPayload register_payload(name);
    RequestPayload request_payload(code, payload_size, { register_payload });

    client.send_header_request(request_header); // Send the header
    client.send_payload_request(request_payload); // Send the request 
}

std::pair<ResponseHeader, ResponsePayload> ClientLogic::receive_registration_response(Client& client) {
    ResponseHeader response_header = client.receive_header_response();
    ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size());
    return { response_header, response_payload }; // Return the response pair
}


std::pair<ResponseHeader, ResponsePayload> ClientLogic::handle_send_public_key_request(Client& client, const std::string& name, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, std::string& base64_private_key, bool *is_fatal_error) {
    for (int counter = 1; counter <= AMOUNT_OF_TRIES; ++counter) {
        logger.log(Logger::Level::INFO, "Attempting to send the public key", __LINE__); // Log that the public key will be sent

        // Generate the public key and send the request
        std::array<uint8_t, SendPublicKeyPayload::LENGTH_OF_PUBLIC_KEY> public_key;
        generate_keys(public_key, base64_private_key);
        send_public_key_request(client, client_id, name, public_key);

        // Receive and handle the response
        auto [response_header, response_payload] = receive_public_key_response(client);
        if (response_header.get_code() == ResponseCode::RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY) {
            return std::make_pair(response_header, response_payload);
        }
        else {
			logger.log(Logger::Level::WARNING, "Attempt to send the public key failed. Retrying...", __LINE__); // Log that the public key wasn't sent successfully
        }
    }

	handle_fatal_error("Public key transfer failed after multiple attempts, due to persistent errors in sending the public key", __LINE__, is_fatal_error); // Handle a fatal error
    return std::make_pair(ResponseHeader(), ResponsePayload());
}

void ClientLogic::send_public_key_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& name, const std::array<uint8_t, SendPublicKeyPayload::LENGTH_OF_PUBLIC_KEY>& public_key) {
	RequestCode code = RequestCode::SEND_PUBLIC_KEY;
	uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::SEND_PUBLIC_KEY_SIZE);

	RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);
	SendPublicKeyPayload send_public_key_payload(name, public_key);
	RequestPayload request_payload(code, payload_size, { send_public_key_payload });

	client.send_header_request(request_header);
	client.send_payload_request(request_payload);
}

std::pair<ResponseHeader, ResponsePayload> ClientLogic::receive_public_key_response(Client& client) {
	ResponseHeader response_header = client.receive_header_response();
	ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size());
	return { response_header, response_payload };
}

void ClientLogic::handle_send_file_progress(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, bool *is_fatal_error) {
    int amount_of_invalid_crc = 0;

    while (amount_of_invalid_crc < INVALUD_CRC_IN_THE_FOURTH_TIME) { // Try to send the file until the amount of invalid CRC is reached
        uint32_t checksum_before = calculate_file_checksum(file_path); // Calculate the checksum before sending the file
        auto [header_response, payload_response] = handle_send_file_request(client, client_id, file_path, aes_key, is_fatal_error); // Send the file
		if (*is_fatal_error) return;
		uint32_t checksum_after = payload_response.get_payload_as<FileReceivedPayload>().get_checksum(); // Get the checksum after sending the file

        if (checksum_before == checksum_after) { // valid crc
            handle_valid_crc_request(client, client_id, file_path, is_fatal_error); // Send the valid crc request
            return;
        }
        else { // invalid crc - we will try to send the file again
			logger.log(Logger::Level::WARNING, "The file wasn't sent successfully - invalid CRC (Attempt " + std::to_string(amount_of_invalid_crc + 1) + ")", __LINE__); // Log that the file wasn't sent successfully
            logger.log(Logger::Level::INFO, "Attempting to send invalid CRC request", __LINE__); // Log that the invalid CRC request will be sent
            handle_invalid_crc_request(client, client_id, file_path, is_fatal_error);
            amount_of_invalid_crc++;
        }
        if (*is_fatal_error)  return;
    }
    handle_invalid_crc_in_fourth_time_request(client, client_id, file_path, is_fatal_error);
}

std::pair<ResponseHeader, ResponsePayload> ClientLogic::handle_send_file_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, bool *is_fatal_error) {
    const uint32_t CHUNK_SIZE_FOR_READ = 4096; // The chunk size for reading the file
    size_t file_size = get_file_size(file_path);
    std::string file_name = extract_file_name_from_path(file_path);
    uint16_t total_packets = static_cast<uint16_t>(std::ceil(static_cast<double>(file_size) / CHUNK_SIZE_FOR_READ)); // Calculate the total packets

    for (int counter_of_tries = 1; counter_of_tries <= AMOUNT_OF_TRIES; ++counter_of_tries) { // Loop through the amount of tries
        logger.log(Logger::Level::INFO, "Attempting to send the file", __LINE__);

        send_file_chunks(client, client_id, file_path, aes_key, file_name, total_packets); // Send the file chunks
        ResponseHeader response_header = client.receive_header_response(); // Receive the response header
        ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size()); // Receive the response payload

        if (response_header.get_code() == ResponseCode::FILE_RECEIVED) {
            return std::make_pair(response_header, response_payload);
        }
        else {
			logger.log(Logger::Level::WARNING, "Attempt to send the file failed. Retrying...", __LINE__); // Log that the file wasn't sent successfully
        }
    }

	handle_fatal_error("File transfer failed after multiple attempts due to persistent errors in sending the file.", __LINE__, is_fatal_error);
    return std::make_pair(ResponseHeader(), ResponsePayload());
}

void ClientLogic::send_file_chunks(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, const std::string& file_name, uint16_t total_packets) {
    const uint32_t CHUNK_SIZE_FOR_READ = 4096; // The chunk size for reading the file
    size_t pos = 0;
    size_t file_size = get_file_size(file_path);

    for (uint16_t packet_number = 1; packet_number <= total_packets; packet_number++) { // Loop through the total packets

        uint32_t original_file_size = std::min(CHUNK_SIZE_FOR_READ, static_cast<uint32_t>(file_size - pos));
        std::string content = read_file_content(file_path, pos, original_file_size);

        // Encrypt the content
        std::string encrypted_content = encrypt_data_by_aes_key(content, aes_key);
        send_file_packet(client, client_id, file_name, packet_number, total_packets, original_file_size, encrypted_content);

        pos += original_file_size;
    }
}

void ClientLogic::send_file_packet(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_name, uint16_t packet_number, uint16_t total_packets, uint32_t original_file_size, const std::string& encrypted_content) {
    RequestCode code = RequestCode::SEND_FILE;
    uint32_t content_size = static_cast<uint32_t>(encrypted_content.size());
    uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::SEND_FILE_BASIC_SIZE) + content_size;

    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);
    SendFilePayload send_file_payload(file_name, content_size, original_file_size, packet_number, total_packets, encrypted_content);
    RequestPayload request_payload(code, payload_size, { send_file_payload });

    client.send_header_request(request_header);
    client.send_payload_request(request_payload);
}

void ClientLogic::handle_valid_crc_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error) {
    int counter_of_tries = 1;
    RequestCode code = RequestCode::VALID_CRC;
    uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::VALID_CRC_SIZE);
    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);

    std::string file_name = extract_file_name_from_path(file_path);
    CrcValidPayload crc_valid_payload(file_name);
    RequestPayload request_payload(code, payload_size, { crc_valid_payload });

    while (counter_of_tries <= AMOUNT_OF_TRIES) {
        logger.log(Logger::Level::DEBUG, "Attempting to send valid CRC request", __LINE__); // Log that the valid CRC request will be sent
        client.send_header_request(request_header);
        client.send_payload_request(request_payload);

        ResponseHeader response_header = client.receive_header_response();
        ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size());
        if (response_header.get_code() == ResponseCode::ACCEPT_MESSAGE) {
            logger.log(Logger::Level::INFO, "The file was sent successfully", __LINE__); // Log that the file was sent successfully
            return;
        }
        else {
            logger.log(Logger::Level::DEBUG, "Failed to send valid CRC request. Retrying...", __LINE__); // Log that the valid CRC request failed
            counter_of_tries++;
        }
    }
    handle_fatal_error("Failed to send valid CRC request, due to persistent errors in sending the valid CRC request", __LINE__, is_fatal_error); // Handle a fatal
}

void ClientLogic::handle_invalid_crc_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error) {
    RequestCode code = RequestCode::INVALID_CRC;
    uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::INVALID_CRC_SIZE);
    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);

    std::string file_name = extract_file_name_from_path(file_path);
    CrcInvalidPayload crc_invalid_payload(file_name);
    RequestPayload request_payload(code, payload_size, { crc_invalid_payload });

    client.send_header_request(request_header);
    client.send_payload_request(request_payload);
}

void ClientLogic::handle_invalid_crc_in_fourth_time_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error) {
    const int max_retries = AMOUNT_OF_TRIES;
    const RequestCode code = RequestCode::INVALID_CRC_IN_THE_FOURTH_TIME;
    const uint32_t payload_size = static_cast<uint32_t>(RequestPayloadSize::INVALID_CRC_IN_THE_FOURTH_TIME_SIZE);

    RequestHeader request_header(client_id, RequestHeader::CLIENT_VERSION, code, payload_size);
    std::string file_name = extract_file_name_from_path(file_path);
    CrcInvalidInFourthTimePayload crc_invalid_in_fourth_time_payload(file_name);
    RequestPayload request_payload(code, payload_size, { crc_invalid_in_fourth_time_payload });

    for (int counter_of_tries = 1; counter_of_tries <= max_retries; ++counter_of_tries) {
        logger.log(Logger::Level::DEBUG, "Attempting to send invalid CRC in fourth time request", __LINE__); // Log that the invalid CRC in the fourth time request will be sent

        client.send_header_request(request_header);
        client.send_payload_request(request_payload);

        ResponseHeader response_header = client.receive_header_response();
        ResponsePayload response_payload = client.receive_payload_response(response_header.get_code(), response_header.get_payload_size());

        if (response_header.get_code() == ResponseCode::ACCEPT_MESSAGE) {
			handle_fatal_error("The file wasn't sent successfully - after 4 attempts with invalid CRC", __LINE__, is_fatal_error); // Handle a fatal error
            return;  // Exit after logging the warning, no further action needed
        }
        else {
            logger.log(Logger::Level::WARNING, "Attempt to send the request - invalid CRC in fourth time failed. Retrying...", __LINE__); // Log that the invalid CRC in the fourth time request failed
        }
    }

    handle_fatal_error("Failed to send invalid CRC in fourth time request, due to persistent errors in sending the invalid CRC in fourth time request", __LINE__, is_fatal_error); // Handle a fatal error
}


void ClientLogic::handle_fatal_error(const std::string& error_message, int line, bool *is_fatal_error) {
    fatal_error(error_message, line, logger); // fatal error
	*is_fatal_error = true; // Update the flag to indicate a fatal error
}