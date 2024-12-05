#include <iomanip>
#include <stdexcept>
#include <string>
#include "client.h"
#include "protocol.h"
#include "logger.h"
#include "utils/bytes_utils.h"

static Logger logger(__FILE__);


Client::Client(const std::string& ip, const std::string& port) : ip(ip), port(port), socket(io_context) {
    if (!connect_to_server()) {
        throw std::runtime_error("Failed to connect to the server: " + ip + ":" + port);
    }
	this->is_little_endian = check_little_endian(); // Check if the system is little endian or big endian
}

Client::~Client() {
	if (socket.is_open()) { // Check if the socket is open
		logger.log(Logger::Level::INFO, "Closing connection to server " + ip + ":" + port, __LINE__);
        socket.close();
    }
}

bool Client::connect_to_server() {
    try {
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(ip, port);
        boost::asio::connect(socket, endpoints);
		logger.log(Logger::Level::INFO, "Successfully connected to server " + ip + ":" + port, __LINE__); // Log the successful connection

    }
    catch (const std::exception& e) {
        logger.log(Logger::Level::PROBLEM, "Unable to connect to server " + ip + ":" + port + " - " + std::string(e.what()), __LINE__);
        return false;
    }
    return true;
}

void Client::send_header_request(const RequestHeader& request_header) {
    std::array<uint8_t, RequestHeader::HEADER_SIZE> header_packed_data;

    try {
        header_packed_data = request_header.pack_header(); // Pack the header data
    }
    catch (...) {
		throw std::runtime_error("Failed to pack header data");
    }

    try {
		if (!is_little_endian) { // Check if the system is big endian
            swap_bytes(header_packed_data.data(), RequestHeader::HEADER_SIZE);
        }

		boost::asio::write(socket, boost::asio::buffer(header_packed_data), RequestHeader::HEADER_SIZE); // Send the header data
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to send header data to the server: " + std::string(e.what()));
    }
}

void Client::send_payload_request(const RequestPayload& request_payload) {
	uint32_t payload_size = request_payload.get_payload_size(); // Get the payload size

    std::vector<uint8_t> payload_packed_data;

    try {
		payload_packed_data = request_payload.pack_payload(); // Pack the payload data
    }
	catch (...) {
		throw std::runtime_error("Failed to pack payload data");
	}

    try {
        size_t total_bytes_sent = 0; // Keep track of total bytes 
        while (total_bytes_sent < payload_size) { 
			size_t remaining_bytes = payload_size - total_bytes_sent;  // Calculate the remaining bytes
            size_t chunk_size = std::min(remaining_bytes, static_cast<size_t>(CHUNK_SIZE));

			if (!is_little_endian) { // Check if the system is big endian
				swap_bytes(payload_packed_data.data() + total_bytes_sent, chunk_size);
            }

			boost::asio::write(socket, boost::asio::buffer(payload_packed_data.data() + total_bytes_sent, chunk_size)); // Send the chunk

			total_bytes_sent += chunk_size; // Update the total bytes sent
        }
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to send payload data to the server: " + std::string(e.what()));
    }
}

ResponseHeader Client::receive_header_response() {
	std::array<uint8_t, ResponseHeader::HEADER_SIZE> header_data; // Prepare the vector to hold the header data
    try {
		boost::asio::read(socket, boost::asio::buffer(header_data), ResponseHeader::HEADER_SIZE); // Receive the header data

		if (!is_little_endian) { // Check if the system is big endian
			swap_bytes(header_data.data(), ResponseHeader::HEADER_SIZE);
		}
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to receive header data from the server: " + std::string(e.what()));
    }

    ResponseHeader response_header;
    try {
        response_header = ResponseHeader::unpack_header(header_data); // Unpack the header data
    }
	catch (...) {
		throw std::runtime_error("Failed to unpack header data");
	}

	return response_header;
}


ResponsePayload Client::receive_payload_response(ResponseCode response_code, uint32_t payload_size) {
    std::vector<uint8_t> payload_data(payload_size); // Prepare the vector to hold the payload data
    size_t total_bytes_received = 0; // Initialize the total received bytes counter
    try {
        while (total_bytes_received < payload_size) {
			size_t remaining_bytes = payload_size - total_bytes_received; // Calculate the remaining bytes
			size_t chunk_size = std::min(remaining_bytes, static_cast<size_t>(CHUNK_SIZE)); // Calculate the chunk size

			boost::asio::read(socket, boost::asio::buffer(payload_data.data() + total_bytes_received, chunk_size)); // Receive the chunk

			if (!is_little_endian) { // Check if the system is big endian
                swap_bytes(payload_data.data() + total_bytes_received, chunk_size);
			}

			total_bytes_received += chunk_size; // Update the total received bytes
        }
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Failed to receive payload data from the server: " + std::string(e.what()));
    }

	ResponsePayload response_payload;
	try {
		response_payload = ResponsePayload::unpack_payload(response_code, payload_data); // Unpack the payload data
	}
    catch (...) {
		throw std::runtime_error("Failed to unpack payload data");
    }

	return response_payload;
}


bool Client::check_little_endian() const{
	unsigned int x = 1;
	char* c = reinterpret_cast<char*>(&x);
	return c[0] == 1; // Check if the first byte is 1
}