#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <cstdint>
#include <variant>
#include <vector>
#include <array>


/**
 * Enum class for various request codes used in the communication protocol.
 *
 * This enum class defines different types of requests that can be made by a
 * client when communicating with the server. Each request type is associated with
 * a unique numeric value, allowing the server to identify the specific action
 * requested by the client.
*/
enum class RequestCode : uint16_t {
    REGISTRATION = 825,
    SEND_PUBLIC_KEY = 826,
    RECONNECT = 827,
    SEND_FILE = 828,
    VALID_CRC = 900,
    INVALID_CRC = 901,
    INVALID_CRC_IN_THE_FOURTH_TIME = 902
};

/**
 * Enum class for various response codes used in the communication protocol.
 *
 * This enum class defines different types of responses that can be sent by the
 * server when communicating with the client. Each response type is associated with
 * a unique numeric value, allowing the client to identify the result of the action
 * that was requested previously by him.
*/
enum class ResponseCode : uint16_t {
    REGISTRATION_SUCCEEDED = 1600,
    REGISTRATION_FAILED = 1601,
    RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY = 1602,
    FILE_RECEIVED = 1603,
    ACCEPT_MESSAGE = 1604,
    RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY = 1605,
    RECONNECT_REQUEST_REJECTED = 1606,
    GENERAL_ERROR = 1607
};

/**
 * Enum class that defines the sizes of various response payloads.
 *
 * This enum contains the sum of all the sizes of the constant fields of the request's
 * payload. Some fields may have variable sizes, and their sizes will be added to the
 * constant sizes as needed. This helps in determining the total size required for
 * each request type.
*/
enum class RequestPayloadSize : uint32_t {
    REGISTRATION_SIZE = 255,
    SEND_PUBLIC_KEY_SIZE = 415,
    RECONNECT_SIZE = 255,
    SEND_FILE_BASIC_SIZE = 267, // Variable size
    VALID_CRC_SIZE = 255,
    INVALID_CRC_SIZE = 255,
    INVALID_CRC_IN_THE_FOURTH_TIME_SIZE = 255
};


#pragma region Structs for Request Payloads

/**
 * Structure that representing the payload for a registration request.
 *
*/
struct RegisterPayload {
public:

    static constexpr size_t NAME_SIZE = 255;

    /**
     * Default constructor for the RegisterPayload struct.
    */
    RegisterPayload() = default;
    /**
     * Constructor for the RegisterPayload struct.
     *
     * Parameters:
     *     name: The name of the client for registration.
    */
    RegisterPayload(const std::string& name);
    /**
     * Overloaded assignment operator for the RegisterPayload struct.
     *
     * Parameters:
     *     other: The RegisterPayload object to copy from.
     *
     * Returns:
     *     A reference to the current RegisterPayload object.
    */
    RegisterPayload& operator=(const RegisterPayload& other);
    /**
     * Method to pack the content of the register payload data into bytes.
     *
     * Returns:
     *     A vector of bytes containing the packed data.
     *
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_name() const { return name; }

private:
    std::string name; // Name of the client

};

/**
 * Structure that representing the payload for sending a public key request.
 *
*/
struct SendPublicKeyPayload {
public:
    static constexpr size_t NAME_SIZE = 255;
    static constexpr size_t LENGTH_OF_PUBLIC_KEY = 160;

    /**
     * Default constructor for the SendPublicKeyPayload struct.
    */
    SendPublicKeyPayload() = default;
    /**
     * Constructor for the SendPublicKeyPayload struct.
     *
     * Parameters:
     *     name: The name of the client for registration.
     *     public_key: The public key of the client.
    */
    SendPublicKeyPayload(const std::string& name, const std::array<uint8_t, LENGTH_OF_PUBLIC_KEY>& public_key);
    /**
     * Overloaded assignment operator for the SendPublicKeyPayload struct.
     *
     * Parameters:
     *     other: The SendPublicKeyPayload object to copy from.
     *
     * Returns:
     *     A reference to the current SendPublicKeyPayload object.
    */
    SendPublicKeyPayload& operator=(const SendPublicKeyPayload& other);
    /**
     * Method to pack the content of the send public key payload data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_name() const { return name; }
    const std::array<uint8_t, LENGTH_OF_PUBLIC_KEY>& get_public_key() const { return public_key; }
private:
    std::string name;  // Name of the client
    std::array<uint8_t, LENGTH_OF_PUBLIC_KEY> public_key; // Public key of the client 

};

/**
 * Structure that representing the payload for a reconnect request.
 *
*/
struct ReconnectPayload {
public:

    static constexpr size_t NAME_SIZE = 255;

    /**
     * Default constructor for the ReconnectPayload struct.
    */
    ReconnectPayload() = default;
    /**
     * Constructor for the ReconnectPayload struct.
     *
     * Parameters:
     *     name: The name of the client for registration.
    */
    ReconnectPayload(const std::string& name);
    /**
     * Overloaded assignment operator for the ReconnectPayload struct.
     *
     * Parameters:
     *     other: The ReconnectPayload object to copy from.
     *
     * Returns:
     *     A reference to the current ReconnectPayload object.
    */
    ReconnectPayload& operator=(const ReconnectPayload& other);
    /**
     * Method to pack the content of the reconnect payload data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_name() const { return name; }
private:
    std::string name; // Name of the client

};

/**
 * Structure that representing the payload for sending a file request.
 *
*/
struct SendFilePayload {
public:

    static constexpr size_t FILE_NAME_SIZE = 255;

    /**
     * Default constructor for the SendFilePayload struct.
    */
    SendFilePayload() = default;
    /**
     * Constructor for the SendFilePayload struct.
     *
     * Parameters:
     *     file_name: The name of the file to send.
     *     content_size: The size of the encrypted content.
     *     original_file_size: The size of the original file.
     *     packet_number: The packet number.
     *     total_packets: The total number of packets.
     *     content: The encrypted content.
    */
    SendFilePayload(const std::string& file_name, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, const std::string& encrypted_content);
    /**
     * Overloaded assignment operator for the SendFilePayload struct.
     *
     * Parameters:
     *     other: The SendFilePayload object to copy from.
     *
     * Returns:
     *     A reference to the current SendFilePayload object.
    */
    SendFilePayload& operator=(const SendFilePayload& other);
    /**
     * Method to pack the content of the send file payload data into bytes.
     *
     * Returns:
     *     A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_file_name() const { return file_name; }
    uint32_t get_content_size() const { return content_size; }
    uint32_t get_original_file_size() const { return original_file_size; }
    uint16_t get_packet_number() const { return packet_number; }
    uint16_t get_total_packets() const { return total_packets; }
	const std::string& get_encrypted_content() const { return encrypted_content; }
private:
    uint32_t content_size; // Size of the encrypted content
    uint32_t original_file_size; // Size of the original file
    uint16_t packet_number; // Packet number
    uint16_t total_packets; // Total number of packets
    std::string file_name; // Name of the file
    std::string encrypted_content; // Encrypted content

};

/**
 * Structure that representing the payload for a valid CRC request.
 *
*/
struct CrcValidPayload {
public:

    static constexpr size_t FILE_NAME_SIZE = 255;

    /**
     * Default constructor for the CrcValidPayload struct.
    */
    CrcValidPayload() = default;
    /**
     * Constructor for the CrcValidPayload struct.
     *
     * Parameters:
     *     file_name: The name of the file.
    */
    CrcValidPayload(const std::string& file_name);
    /**
     * Overloaded assignment operator for the CrcValidPayload struct.
     *
     * Parameters:
     *     other: The CrcValidPayload object to copy from.
     *
     * Returns:
     *     A reference to the current CrcValidPayload object.
    */
    CrcValidPayload& operator=(const CrcValidPayload& other);
    /**
     * Method to pack the content of the valid CRC payload data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_file_name() const { return file_name; }
private:
    std::string file_name; // Name of the file

};

/**
 * Structure that representing the payload for an invalid CRC request.
 *
*/
struct CrcInvalidPayload {
public:

    static constexpr size_t FILE_NAME_SIZE = 255;

    /**
     * Default constructor for the CrcInvalidPayload struct.
    */
    CrcInvalidPayload() = default;
    /**
     * Constructor for the CrcInvalidPayload struct.
     *
     * Parameters:
     *     file_name: The name of the file.
    */
    CrcInvalidPayload(const std::string& file_name);
    /**
     * Overloaded assignment operator for the CrcInvalidPayload struct.
     *
     * Parameters:
     *     other: The CrcInvalidPayload object to copy from.
     *
     * Returns:
     *     A reference to the current CrcInvalidPayload object.
    */
    CrcInvalidPayload& operator=(const CrcInvalidPayload& other);
    /**
     * Method to pack the content of the invalid CRC payload data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_file_name() const { return file_name; }
private:
    std::string file_name; // Name of the file

};

/**
 * Structure that representing the payload for an invalid CRC request after the fourth time.
 *
*/
struct CrcInvalidInFourthTimePayload {
public:

    static constexpr size_t FILE_NAME_SIZE = 255;

    /**
     * Default constructor for the CrcInvalidInFourthTimePayload struct.
    */
    CrcInvalidInFourthTimePayload() = default;
    /**
     * Constructor for the CrcInvalidInFourthTimePayload struct.
     *
     * Parameters:
     *     file_name: The name of the file.
    */
    CrcInvalidInFourthTimePayload(const std::string& file_name);
    /**
     * Overloaded assignment operator for the CrcInvalidInFourthTimePayload struct.
     *
     * Parameters:
     *     other: The CrcInvalidInFourthTimePayload object to copy from.
     *
     * Returns:
     *     A reference to the current CrcInvalidInFourthTimePayload object.
    */
    CrcInvalidInFourthTimePayload& operator=(const CrcInvalidInFourthTimePayload& other);
    /**
     * Method to pack the content of the invalid CRC payload data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack() const;

    // Getters
    const std::string& get_file_name() const { return file_name; }
private:
    std::string file_name; // Name of the file

};
#pragma endregion


#pragma region Structs for Response Payloads

/**
 * Structure that representing the payload for a successful registration response.
 *
*/
struct RegisterSuccessedPayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;

    /**
     * Default constructor for the RegisterSuccessedPayload struct.
    */
    RegisterSuccessedPayload() = default;
    /**
     * Constructor for the RegisterSuccessedPayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
    */
    RegisterSuccessedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id);
    /**
     * Overloaded assignment operator for the RegisterSuccessedPayload struct.
     *
     * Parameters:
     *     other: The RegisterSuccessedPayload object to copy from.
     *
     * Returns:
     *     A reference to the current RegisterSuccessedPayload object.
    */
    RegisterSuccessedPayload& operator=(const RegisterSuccessedPayload& other);
    /**
     * Method to unpack the content of the register successed payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *    A RegisterSuccessedPayload object containing the unpacked data.
    */
    static RegisterSuccessedPayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
private:
    std::array<uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)

};

/**
 * Structure that representing the payload for a failed registration response.
 *
*/
struct RegisterFailedPayload {
    /**
     * Default constructor for the RegisterFailedPayload struct.
    */
    RegisterFailedPayload() {};
    /**
     * Method to unpack the content of the register failed payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     * Returns:
     *     A RegisterFailedPayload object containing the unpacked data.
    */
    static RegisterFailedPayload unpack(std::vector<uint8_t>& data) { return RegisterFailedPayload(); }
};

/**
 * Structure that representing the payload for receiving an encrypted AES key response.
 * after sending the public key.
 *
*/
struct ReceivedEncryptedAesKeyPayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;

    /**
     * Default constructor for the ReceivedEncryptedAesKeyPayload struct.
    */
    ReceivedEncryptedAesKeyPayload() = default;
    /**
     * Constructor for the ReceivedEncryptedAesKeyPayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
     *     aes_encrypted_key: The encrypted AES key.
    */
    ReceivedEncryptedAesKeyPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, const std::string& aes_encrypted_key);
    /**
     * Overloaded assignment operator for the ReceivedEncryptedAesKeyPayload struct.
     *
     * Parameters:
     *     other: The ReceivedEncryptedAesKeyPayload object to copy from.
     *
     * Returns:
     *     A reference to the current ReceivedEncryptedAesKeyPayload object.
    */
    ReceivedEncryptedAesKeyPayload& operator=(const ReceivedEncryptedAesKeyPayload& other);
    /**
     * Method to unpack the content of the received encrypted AES key payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A ReceivedEncryptedAesKeyPayload object containing the unpacked data.
    */
    static ReceivedEncryptedAesKeyPayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
    const std::string& get_aes_encrypted_key() const { return aes_encrypted_key; }
private:
    std::array <uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)
    std::string  aes_encrypted_key; // Encrypted AES key
};

/**
 * Structure that representing the payload for receiving a file with valid CRC response.
 *
*/
struct FileReceivedPayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;
    static constexpr size_t FILE_NAME_SIZE = 255;

    /**
     * Default constructor for the FileReceivedPayload struct.
    */
    FileReceivedPayload() = default;
    /**
     * Constructor for the FileReceivedPayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
     *     content_size: The size of the content.
     *     file_name: The name of the file.
     *     check_sum: The check sum of the file.
     *
    */
    FileReceivedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, uint16_t content_size, const std::string& file_name, uint32_t checksum);
    /**
     * Overloaded assignment operator for the FileReceivedPayload struct.
     *
     * Parameters:
     *     other: The FileReceivedPayload object to copy from.
     *
     * Returns:
     *     A reference to the current FileReceivedPayload object.
    */
    FileReceivedPayload& operator=(const FileReceivedPayload& other);
    /**
     * Method to unpack the content of the file received with valid CRC payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A FileReceived object containing the unpacked data.
    */
    static FileReceivedPayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
    uint16_t get_content_size() const { return content_size; }
    const std::string& get_file_name() const { return file_name; }
    uint32_t get_checksum() const { return checksum; }
private:
    std::array <uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)
    uint16_t content_size; // Size of the content
    std::string file_name; // Name of the file
    uint32_t checksum; // Check sum of the file
};

/**
 * Structure that representing the payload for an accept message response.
 *
*/
struct AcceptMessagePayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;

    /**
     * Default constructor for the AcceptMessagePayload struct.
    */
    AcceptMessagePayload() = default;
    /**
     * Constructor for the AcceptMessagePayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
    */
    AcceptMessagePayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id);
    /**
     * Overloaded assignment operator for the AcceptMessagePayload struct.
     *
     * Parameters:
     *     other: The AcceptMessagePayload object to copy from.
     *
     * Returns:
     *     A reference to the current AcceptMessagePayload object.
    */
    AcceptMessagePayload& operator=(const AcceptMessagePayload& other);
    /**
     * Method to unpack the content of the accept message payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A AcceptMessagePayload object containing the unpacked data.
    */
    static AcceptMessagePayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
private:
    std::array <uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)
};

/**
 * Structure that representing the payload for a reconnect request accepted response.
 *
*/
struct ReconnectRequestAcceptedPayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;

    /**
     * Default constructor for the ReconnectRequestAcceptedPayload struct.
    */
    ReconnectRequestAcceptedPayload() = default;
    /**
     * Constructor for the ReconnectRequestAcceptedPayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
     *     aes_encrypted_key: The encrypted AES key.
    */
    ReconnectRequestAcceptedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, const std::string& aes_encrypted_key);
    /**
     * Overloaded assignment operator for the ReconnectRequestAcceptedPayload struct.
     *
     * Parameters:
     *     other: The ReconnectRequestAcceptedPayload object to copy from.
     *
     * Returns:
     *     A reference to the current ReconnectRequestAcceptedPayload object.
    */
    ReconnectRequestAcceptedPayload& operator=(const ReconnectRequestAcceptedPayload& other);
    /**
     * Method to unpack the content of the reconnect request accepted payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A ReconnectRequestAcceptedPayload object containing the unpacked data.
    */
    static ReconnectRequestAcceptedPayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
	const std::string& get_aes_encrypted_key() const { return aes_encrypted_key; }
private:
    std::array <uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)
    std::string aes_encrypted_key; // Encrypted AES key
};

/**
 * Structure that representing the payload for a reconnect request rejected response.
 *
*/
struct ReconnectRequestRejectedPayload {
public:

    static constexpr size_t CLIENT_ID_SIZE = 16;

    /**
     * Default constructor for the ReconnectRequestRejectedPayload struct.
    */
    ReconnectRequestRejectedPayload() = default;
    /**
     * Constructor for the ReconnectRequestRejectedPayload struct.
     *
     * Parameters:
     *     client_id: The client ID that the server assigned.
    */
    ReconnectRequestRejectedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id);
    /**
     * Overloaded assignment operator for the ReconnectRequestRejectedPayload struct.
     *
     * Parameters:
     *     other: The ReconnectRequestRejectedPayload object to copy from.
     *
     * Returns:
     *     A reference to the current ReconnectRequestRejectedPayload object.
    */
    ReconnectRequestRejectedPayload& operator=(const ReconnectRequestRejectedPayload& other);
    /**
     * Method to unpack the content of the reconnect request rejected payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A ReconnectRequestRejectedPayload object containing the unpacked data.
    */
    static ReconnectRequestRejectedPayload unpack(std::vector<uint8_t>& data);

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
public:
    std::array <uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)    
};

/**
 * Structure that representing the payload for a general error response.
 *
*/
struct GeneralErrorPayload {
    /**
     * Default constructor for the GeneralErrorPayload struct.
    */
    GeneralErrorPayload() = default;
    /**
     * Method to unpack the content of the general error payload data from bytes.
     *
     * Parameters:
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A GeneralErrorPayload object containing the unpacked data.
    */
    static GeneralErrorPayload unpack(std::vector<uint8_t>& data) { return GeneralErrorPayload(); }
};
#pragma endregion


// Variant type to hold any of the possible request payloads
using RequestPayloadTypes = std::variant<
    RegisterPayload,
    SendPublicKeyPayload,
    ReconnectPayload,
    SendFilePayload,
    CrcValidPayload,
    CrcInvalidPayload,
    CrcInvalidInFourthTimePayload
>;

// Variant type to hold any of the possible response payloads
using ResponsePayloadTypes = std::variant<
    RegisterSuccessedPayload,
    RegisterFailedPayload,
    ReceivedEncryptedAesKeyPayload,
    FileReceivedPayload,
    AcceptMessagePayload,
    ReconnectRequestAcceptedPayload,
    ReconnectRequestRejectedPayload,
    GeneralErrorPayload
>;


/**
 * Class that represents the header of a request.
 *
*/
class RequestHeader
{
public:
    static constexpr size_t CLIENT_ID_SIZE = 16; // Size of the client ID
    static constexpr size_t HEADER_SIZE = 23; // Size of the header
    static constexpr uint8_t CLIENT_VERSION = 3; // Version of the client

    /**
     * Constructor for the RequestHeader class.
     *
     * Parameters:
     *     client_id: The client ID.
     *     version: The version of the client.
     *     code: The code of the request.
     *     payload_size: The size of the payload.
    */
    RequestHeader(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, uint8_t version, RequestCode code, uint32_t payload_size);
    /**
     * Method to pack the content of the request header data into bytes.
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::array<uint8_t, HEADER_SIZE> pack_header() const;

    // Getters
    const std::array<uint8_t, CLIENT_ID_SIZE>& get_client_id() const { return client_id; }
    const uint8_t get_version() const { return version; }
    const RequestCode get_code() const { return code; }
    const uint32_t get_payload_size() const { return payload_size; }

private:
    std::array<uint8_t, CLIENT_ID_SIZE> client_id; // Client ID (16 bytes)
    uint8_t version; // Version (1 byte)
    RequestCode code; // Code (2 bytes)
    uint32_t payload_size; // Size of payload (4 bytes)

};

/**
 * Class that represents the payload of a request.
 *
*/
class RequestPayload
{
public:
    /**
     * Constructor for the RequestPayload class.
     *
     * Parameters:
     *     code: The code of the request.
	 *      payload_size: The size of the payload.
     *     values: The values of the request payload.
    */
    RequestPayload(RequestCode code, uint32_t payload_size, RequestPayloadTypes payload)
        : code(code), payload_size(payload_size), payload(std::move(payload)) {}

    /**
     * Method to pack the content of the request payload data into bytes.
     *
     *
     * Returns:
     *    A vector of bytes containing the packed data.
    */
    std::vector<uint8_t> pack_payload() const;

    // Getters
    const RequestCode get_request_code() const { return code; }
    const uint32_t get_payload_size() const { return payload_size; }

	/**
	* Method to get the payload as a specific type.
	*
	* Returns:
	*     The payload as the specified type.
	*/
    template<typename T>
    const T& get_payload_as() const {
        if (std::holds_alternative<T>(payload)) {
            return std::get<T>(payload);
        }
        throw std::bad_variant_access();
    }

private:
    RequestCode code; // Code of the request
    uint32_t payload_size; // Size of the payload 
    RequestPayloadTypes payload; // The payload variant
};

/**
 * Class that represents the header of a response.
 *
*/
class ResponseHeader
{
public:

    static constexpr size_t HEADER_SIZE = 7; // Size of the header


	ResponseHeader() = default;

    /**
     * Constructor for the ResponseHeader class.
     *
     * Parameters:
     *     version: The version of the server.
     *     code: The code of the response.
     *     payload_size: The size of the payload.
     *
    */
    ResponseHeader(uint8_t version, ResponseCode code, uint32_t payload_size);
    /**
     * Method to unpack the content of the response header data from bytes.
     *
     * Parameters:
     *     data: The array of bytes containing the packed data.
     *
     * Returns:
     *     A ResponseHeader object containing the unpacked data.
    */
    static ResponseHeader unpack_header(std::array<uint8_t, HEADER_SIZE>& data);

    // Getters
    const uint8_t get_version() const { return version; }
    const ResponseCode get_code() const { return code; }
    const uint32_t get_payload_size() const { return payload_size; }

private:
    uint8_t version; // Version (1 byte)
    ResponseCode code; // Response code (2 bytes)
    uint32_t payload_size; // Size of payload (4 bytes)
};


/**
 * Class that represents the payload of a response.
 *
 */ 
class ResponsePayload {
public:

    /**
     * Default constructor for the ResponsePayload class.
     */
	ResponsePayload() = default;

    /**
     * Constructor for the ResponsePayload class.
     *
     * Parameters:
     *     payload: The payload of the response.
     */
    ResponsePayload(ResponsePayloadTypes payload) : payload(std::move(payload)) {}

    /**
     * Method to unpack the content of the response payload data from bytes.
     *
     * Parameters:
     *     code: The code of the response, according we will unpack the payload.
     *     data: The vector of bytes containing the packed data.
     *
     * Returns:
     *     A ResponsePayload object containing the unpacked data.
     */
    static ResponsePayload unpack_payload(ResponseCode code, std::vector<uint8_t>& data);

    /**
     * Method to get the payload as a specific type.
     *
     * Returns:
     *     The payload as the specified type.
     */
    template<typename T>
    const T& get_payload_as() const {
        if (std::holds_alternative<T>(payload)) {
            return std::get<T>(payload);
        }
        throw std::bad_variant_access();
    }

private:
    ResponsePayloadTypes payload;
};


#endif // PROTOCOL_H