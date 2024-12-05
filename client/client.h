#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#define BOOST_DISABLE_CURRENT_LOCATION
#include <boost/asio.hpp>
#include "protocol.h"


/**
 * The Client class is responsible for sending and receiving data to and from the server.
 * It uses the Boost.Asio library for asynchronous I/O operations.
 * 
 */
class Client {
public:
    /**
     * Constructor for the Client class.
     *
     * Parameters:
     *     ip: The IP of the server.
     *     port: The port of the server.
     */
    Client(const std::string& ip, const std::string& port);
    /**
     * Destructor for the Client class.
     */
    ~Client();
    /**
     * Method that gets request header object and do packing to it,
     * then send it to the server.
     * 
     * Parameters:
     *     request_header: The request header data (after packing) to send to the server.
     */
    void send_header_request(const RequestHeader& request_header);
    /**
     * Method that gets request payload object and do packing to it,
     * then send it to the server.
     * 
     * Parameters:
     *     request_payload: The request payload data (after packing) to send to the server.
     */
    void send_payload_request(const RequestPayload& request_payload);
    /**
     * Method that receives the response header data from the server,
     * unpacks it, and returns the response header object.
     * 
     * Returns:
     *     The response header (after unpacking) received from the server.
     */
    ResponseHeader receive_header_response();
    /**
     * Method that receives the response payload data from the server,
     * unpacks it, and returns the response payload object.
     * 
     * Parameters:
     *     response_code: The response code received from the server.
     *     payload_size: The size of the payload to receive.
     * 
     * Returns:
     *     The response payload (after unpacking) received from the server.
     */
    ResponsePayload receive_payload_response(ResponseCode response_code, uint32_t payload_size);
private:
	static constexpr int CHUNK_SIZE = 1024; // Chunk size for sending data from the client to the server

    std::string port; // Port of the server
    std::string ip; // IP of the server
    boost::asio::io_context io_context; // IO context
    boost::asio::ip::tcp::socket socket{ io_context }; // Socket
	bool is_little_endian; // Flag to check if the system is little endian

    /**
     * Method that try to connect to the server.
     *
     * Returns:
     *     true if the connection to the server was successful, false otherwise.
     */
    bool connect_to_server();
	/**
	* Method that checks if the system is little endian.
	*
	* Returns:
	* 	   true if the system is little endian, false otherwise.
    */
    bool check_little_endian() const;
};

#endif // CLIENT_H
