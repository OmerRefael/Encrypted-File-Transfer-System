#ifndef CLIENT_LOGIC_H
#define CLIENT_LOGIC_H

#include <string>
#include <array>
#include <memory>
#include "client.h"
#include "file_handler.h"
#include "protocol.h"


class ClientLogic {
public:
    /**
    * Handles the reconnect process for the client.
    *
    * This function attempts to reconnect the client by sending a reconnect request
    * to the server and processing the response accordingly. If the reconnect
    * request is accepted, it proceeds with the reconnect accepted process. If
    * rejected, it starts the registration process.
    *
    * Parameters:
    *     client : The client attempting to reconnect.
    *     transfer_file_data : Unique pointer containing transfer information.
    *     user_file_data : Unique pointer containing user information.
    *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
    */
    static void handle_reconnect_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error);

    /**
     * Handles the registration process for the client.
     *
     * This function sends a registration request to the server and processes
     * the response. If successful, it proceeds with the registration success
     * process; otherwise, it handles the registration failure.
     *
     * Parameters:
     *     client : The client that is registering.
     *     transfer_file_data : Unique pointer containing transfer information.
     *     user_file_data : Unique pointer containing user information.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_register_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error);

private:
    /**
     * Handles the process when the reconnect request is accepted.
     *
     * This function processes the response from the server when a reconnect
     * request is accepted. It decrypts the AES key and proceeds with sending
     * the file.
     *
     * Parameters:
     *     payload_response : The payload response received from the server.
     *     user_file_data : Unique pointer containing user information.
     *     transfer_file_data : Unique pointer containing transfer information.
     *     client : The client that is reconnecting.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_reconnect_accepted_process(const ResponsePayload& payload_response, std::unique_ptr<user_info_data> user_file_data, std::unique_ptr<transfer_info_data> transfer_file_data, Client& client, bool *is_fatal_error);

    /**
     * Handles the process when the reconnect request is rejected.
     *
     * This function logs the rejection of the reconnect request and initiates
     * the registration process for the client.
     *
     * Parameters:
     *     client : The client that was attempting to reconnect.
     *     transfer_file_data : Unique pointer containing transfer information.
     *     user_file_data : Unique pointer containing user information.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_reconnect_rejected_process(Client& client, std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, bool *is_fatal_error);

    /**
     * Handles the successful registration process.
     *
     * This function processes the successful registration response from the
     * server, updates user information, and sends the public key to the server.
     *
     * Parameters:
     *     transfer_file_data : Unique pointer containing transfer information.
     *     user_file_data : Unique pointer containing user information.
     *     payload_response : The payload response received from the server.
     *     client : The client that has been registered.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_registration_success(std::unique_ptr<transfer_info_data> transfer_file_data, std::unique_ptr<user_info_data> user_file_data, const ResponsePayload& payload_response, Client& client, bool *is_fatal_error);

    /**
     * Handles the registration failure process.
     *
     * This function logs the failure of the registration process and prompts
     * the user to try again with different details.
     */
    static void handle_registration_failure();

    /**
     * Handles the reconnect request process.
     *
     * This function sends a reconnect request to the server and waits for a
     * response, retrying if the response is not as expected.
     *
     * Parameters:
     *     client : The client attempting to reconnect.
     *     name : The name used for the reconnect request.
     *     client_id : The unique identifier for the client.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> handle_reconnect_request(Client& client, const std::string& name, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, bool *is_fatal_error);

    /**
     * Sends a reconnect request to the server.
     *
     * This function constructs and sends a request to reconnect using the
     * provided client ID and name.
     *
     * Parameters:
     *     client : The client sending the reconnect request.
     *     client_id : The unique identifier for the client.
     *     name : The name used for the reconnect request.
     */
    static void send_reconnect_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& name);

    /**
     * Receives the response to the reconnect request.
     *
     * This function waits for the server's response to the reconnect request
     * and returns the response header and payload.
     *
     * Parameters:
     *     client : The client receiving the response.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> receive_reconnect_response(Client& client);


    /**
     * Handles the registration request process.
     *
     * This function attempts to register the client by sending a registration
     * request to the server and waiting for an expected response. It will retry
     * the request a specified number of times if the response is not as expected.
     *
     * Parameters:
     *     client : The client attempting to register.
     *     name : The name to be used for registration.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> handle_registration_request(Client& client, const std::string& name, bool *is_fatal_error);

    /**
     * Sends a registration request to the server.
     *
     * This function constructs and sends a request containing the client's name
     * for registration. The client ID is ignored and set to zero.
     *
     * Parameters:
     *     client : The client sending the registration request.
     *     name : The name to be used for registration.
     */
    static void send_registration_request(Client& client, const std::string& name);

    /**
     * Receives the response to the registration request.
     *
     * This function waits for the server's response to the registration request
     * and returns the response header and payload.
     *
     * Parameters:
     *     client : The client receiving the response.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> receive_registration_response(Client& client);

    /**
     * Handles the process of sending the public key to the server.
     *
     * This function attempts to send the client's public key and waits for an
     * expected response from the server. It will retry the request a specified
     * number of times if the response is not successful.
     *
     * Parameters:
     *     client : The client sending the public key.
     *     name : The name associated with the public key.
     *     client_id : The unique identifier for the client.
     *     base64_private_key : The private key in Base64 format.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> handle_send_public_key_request(Client& client, const std::string& name, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, std::string& base64_private_key, bool *is_fatal_error);

    /**
     * Sends a public key request to the server.
     *
     * This function constructs and sends a request containing the public key and
     * the client's name. The client ID is included in the request.
     *
     * Parameters:
     *     client : The client sending the public key request.
     *     client_id : The unique identifier for the client.
     *     name : The name associated with the public key.
     *     public_key : The public key to be sent.
     */
    static void send_public_key_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& name, const std::array<uint8_t, SendPublicKeyPayload::LENGTH_OF_PUBLIC_KEY>& public_key);

    /**
     * Receives the response to the public key request.
     *
     * This function waits for the server's response to the public key request
     * and returns the response header and payload.
     *
     * Parameters:
     *     client : The client receiving the response.
     *
     * Returns:
     *     A pair containing the response header and payload from the server.
     */
    static std::pair<ResponseHeader, ResponsePayload> receive_public_key_response(Client& client);


    /**
     * Handles the process of sending a file and managing its progress.
     *
     * This function attempts to send a file to a server and validates the CRC
     * of the received file to ensure integrity. If the CRC is invalid, it will
     * retry sending the file a specified number of times. If the file fails
     * to send successfully after the maximum number of retries, an appropriate
     * request will be made.
     *
     * Parameters:
     *     client : The client sending the file.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the file to be sent.
     *     aes_key : The key used for AES encryption of the file content.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */

    static void handle_send_file_progress(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, bool *is_fatal_error);

    /**
     * Sends the file to the server and handles the response.
     *
     * This function breaks the file into chunks, sends each chunk, and waits
     * for a response from the server. It will retry sending the file if it
     * does not receive a successful response within a specified number of attempts.
     *
     * Parameters:
     *     client : The client sending the file.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the file to be sent.
     *     aes_key : The key used for AES encryption of the file content.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     *
     * Returns:
     *     A pair containing the response header and payload.
     */
    static std::pair<ResponseHeader, ResponsePayload> handle_send_file_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, bool *is_fatal_error);

    /**
     * Sends the file in chunks to the server.
     *
     * This function reads the file content in specified chunk sizes and sends
     * each chunk to the server. The file is encrypted using AES before being sent.
     *
     * Parameters:
     *     client : The client sending the file.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the file to be sent.
     *     aes_key : The key used for AES encryption of the file content.
     *     file_name : The name of the file being sent.
     *     total_packets : The total number of packets to be sent.
     */
    static void send_file_chunks(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, const std::string& aes_key, const std::string& file_name, uint16_t total_packets);

    /**
     * Sends a single file packet to the server.
     *
     * This function constructs and sends a packet containing a chunk of the file
     * along with necessary metadata to the server.
     *
     * Parameters:
     *     client : The client sending the file.
     *     client_id : The unique identifier for the client.
     *     file_name : The name of the file being sent.
     *     packet_number : The sequence number of the current packet.
     *     total_packets : The total number of packets to be sent.
     *     original_file_size : The size of the original file being sent.
     *     encrypted_content : The encrypted content of the current file chunk.
     */
    static void send_file_packet(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_name, uint16_t packet_number, uint16_t total_packets, uint32_t original_file_size, const std::string& encrypted_content);

    /**
     * Handles the request when a valid CRC is received.
     *
     * This function sends a request to the server indicating that the file
     * was received successfully with a valid CRC.
     *
     * Parameters:
     *     client : The client confirming the file was received.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the successfully sent file.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_valid_crc_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error);

    /**
     * Handles the request when an invalid CRC is detected.
     *
     * This function sends a request to the server indicating that the file
     * was not received correctly due to an invalid CRC.
     *
     * Parameters:
     *     client : The client reporting the invalid CRC.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the file that had an invalid CRC.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */

    static void handle_invalid_crc_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error);

    /**
     * Handles the request after the fourth failed CRC attempt.
     *
     * This function attempts to inform the server that an invalid CRC was
     * encountered for the fourth time and handles any subsequent actions.
     *
     * Parameters:
     *     client : The client sending the notification.
     *     client_id : The unique identifier for the client.
     *     file_path : The path of the file that repeatedly failed CRC checks.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_invalid_crc_in_fourth_time_request(Client& client, const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, const std::string& file_path, bool *is_fatal_error);

    /**
     * Handles fatal errors encountered during file operations.
     *
     * This function logs the error message and updates the fatal error flag.
     *
     * Parameters:
     *     error_message : The message describing the error.
     *     line : The line number where the error occurred.
     *     is_fatal_error : A shared pointer to a boolean indicating if a fatal error occurred.
     */
    static void handle_fatal_error(const std::string& error_message, int line, bool *is_fatal_error);
};

#endif