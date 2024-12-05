#include <array>
#include <cstdint>
#include <cstring>
#include <variant>
#include <stdexcept>
#include <vector>
#include "protocol.h"

#define FIRST_ELEMENT 0
#define MAX_LENGTH_OF_NAME 100


RequestHeader::RequestHeader(const std::array<uint8_t, RequestHeader::CLIENT_ID_SIZE>& client_id, uint8_t version, RequestCode code, uint32_t payload_size) :
    client_id(client_id), version(version), code(code), payload_size(payload_size)
{
}

std::array<uint8_t, RequestHeader::HEADER_SIZE> RequestHeader::pack_header() const {
    std::array<uint8_t, RequestHeader::HEADER_SIZE> header_packed_data; // Define the packed data of the header request
    std::memcpy(header_packed_data.data(), client_id.data(), sizeof(client_id)); // Pack the client ID
    std::memcpy(header_packed_data.data() + sizeof(client_id), &version, sizeof(version)); // Pack the client version
    std::memcpy(header_packed_data.data() + sizeof(client_id) + sizeof(version), &code, sizeof(code)); // Pack the request code
    std::memcpy(header_packed_data.data() + sizeof(client_id) + sizeof(version) + sizeof(code), &payload_size, sizeof(payload_size)); // Pack the payload size

    return header_packed_data; // Return the packed data
}


std::vector<uint8_t> RequestPayload::pack_payload() const {
    // Implement the packing logic based on the payload type
    std::vector<uint8_t> packed_data;
    // Use std::visit or if-else to handle different payload types
    std::visit([&](const auto& p) {
        // Here you would call a packing method for the specific type
        packed_data = p.pack(); // Ensure that each payload type has a pack() method
        }, payload);
    return packed_data;
}


ResponseHeader::ResponseHeader(uint8_t version, ResponseCode code, uint32_t payload_size) :
    version(version), code(code), payload_size(payload_size)
{
}

ResponseHeader ResponseHeader::unpack_header(std::array<uint8_t, HEADER_SIZE>& data)
{
    uint8_t version; // Version (1 byte)
    ResponseCode code; // ResponseCode code (2 bytes)
    uint32_t payload_size; // Size of payload (4 bytes)

    std::memcpy(&version, data.data(), sizeof(version)); // Unpack the version
    std::memcpy(&code, data.data() + sizeof(version), sizeof(code)); // Unpack the code
    std::memcpy(&payload_size, data.data() + sizeof(version) + sizeof(code), sizeof(payload_size)); // Unpack the payload size

    return ResponseHeader(version, code, payload_size);
}


ResponsePayload  ResponsePayload::unpack_payload(ResponseCode code, std::vector<uint8_t>& data)
{
    switch (code) {
    case ResponseCode::REGISTRATION_SUCCEEDED:
        return ResponsePayload(RegisterSuccessedPayload::unpack(data));
    case ResponseCode::REGISTRATION_FAILED:
        return ResponsePayload(RegisterFailedPayload::unpack(data));
    case ResponseCode::RECEIVED_PUBLIC_KEY_AND_SEND_ENCRYPTED_AES_KEY:
        return ResponsePayload(ReceivedEncryptedAesKeyPayload::unpack(data));
    case ResponseCode::FILE_RECEIVED:
        return ResponsePayload(FileReceivedPayload::unpack(data));
    case ResponseCode::ACCEPT_MESSAGE:
        return ResponsePayload(AcceptMessagePayload::unpack(data));
    case ResponseCode::RECONNECT_REQUEST_ACCEPT_AND_SEND_ENCRYPTED_AES_KEY:
        return ResponsePayload(ReconnectRequestAcceptedPayload::unpack(data));
    case ResponseCode::RECONNECT_REQUEST_REJECTED:
        return ResponsePayload(ReconnectRequestRejectedPayload::unpack(data));
    case ResponseCode::GENERAL_ERROR:
        return ResponsePayload(GeneralErrorPayload::unpack(data));
    default:
        throw std::invalid_argument("Invalid response code");
    }
}



#pragma region RegisterPayload
RegisterPayload::RegisterPayload(const std::string& name) {
    if (name.length() >= MAX_LENGTH_OF_NAME) { // Check if the name is too long - 255 characters max (including null terminator)
        throw std::invalid_argument("Name is too long");
    }
    this->name = name; // Copy the name
	this->name.resize(NAME_SIZE); // Resize the name to the expected size
}

RegisterPayload& RegisterPayload::operator=(const RegisterPayload& other) {
    if (this != &other) {
        name = other.name; // Copy the name
    }
    return *this;
}

std::vector<uint8_t> RegisterPayload::pack() const{
	std::vector<uint8_t> data(NAME_SIZE);
	std::memcpy(data.data(), name.data(), NAME_SIZE); // Copy the name
	return data;
}
#pragma endregion


#pragma region SendPublicKeyPayload
SendPublicKeyPayload::SendPublicKeyPayload(const std::string& name, const std::array<uint8_t, LENGTH_OF_PUBLIC_KEY>& public_key) {
    if (name.length() >= MAX_LENGTH_OF_NAME) { // Check if the name is too long - 255 characters max (including null terminator)
        throw std::invalid_argument("Name is too long");
    }
	this->name = name;
	this->name.resize(NAME_SIZE); // Resize the name to the expected size
    this->public_key = public_key;
}

SendPublicKeyPayload& SendPublicKeyPayload::operator=(const SendPublicKeyPayload& other) {
    if (this != &other) {
        name = other.name;
        public_key = other.public_key;
    }
    return *this;
}

std::vector<uint8_t> SendPublicKeyPayload::pack() const {
	size_t size = NAME_SIZE + LENGTH_OF_PUBLIC_KEY;

    std::vector<uint8_t> data(size); 
	std::memcpy(data.data(), name.data(), NAME_SIZE); // Copy the name
	std::memcpy(data.data() + NAME_SIZE, public_key.data(), LENGTH_OF_PUBLIC_KEY); // Copy the public key
	return data;
}
#pragma endregion

#pragma region ReconnectPayload
ReconnectPayload::ReconnectPayload(const std::string& name) {
    if (name.length() >= MAX_LENGTH_OF_NAME) { // Check if the name is too long - 255 characters max (including null terminator)
        throw std::invalid_argument("Name is too long");
    }
    this->name = name;
	this->name.resize(NAME_SIZE); // Resize the name to the expected size
}

ReconnectPayload& ReconnectPayload::operator=(const ReconnectPayload& other) {
    if (this != &other) {
        name = other.name;
    }
    return *this;
}

std::vector<uint8_t> ReconnectPayload::pack() const {
	std::vector<uint8_t> data(NAME_SIZE);
	std::memcpy(data.data(), name.data(), NAME_SIZE); // Copy the name
	return data;
}
#pragma endregion

#pragma region SendFilePayload

SendFilePayload::SendFilePayload(const std::string& file_name, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, const std::string& encrypted_content) {
    if (file_name.length() >= FILE_NAME_SIZE) { // Check if the name is too long which means that the padding won't fit
        throw std::invalid_argument("File name is too long");
    }
    this->file_name = file_name;
	this->file_name.resize(FILE_NAME_SIZE);
    this->content_size = content_size;
    this->original_file_size = original_file_size;
    this->packet_number = packet_number;
    this->total_packets = total_packets;
    this->encrypted_content = encrypted_content;
}

SendFilePayload& SendFilePayload::operator=(const SendFilePayload& other) {
    if (this != &other) {
        file_name = other.file_name;
        content_size = other.content_size;
        original_file_size = other.original_file_size;
        packet_number = other.packet_number;
        total_packets = other.total_packets;
        encrypted_content = other.encrypted_content;
    }
    return *this;
}

std::vector<uint8_t> SendFilePayload::pack() const {
    size_t size = FILE_NAME_SIZE + sizeof(content_size) + sizeof(original_file_size) + sizeof(packet_number) + sizeof(total_packets) + encrypted_content.size();

    std::vector<uint8_t> data(size);

    size_t offset = 0;

	// Copy the content size value to the buffer
    std::memcpy(data.data() + offset, &content_size, sizeof(content_size));
    offset += sizeof(content_size);

	// Copy the original file size value to the buffer
    std::memcpy(data.data() + offset, &original_file_size, sizeof(original_file_size));
    offset += sizeof(original_file_size);

	// Copy the packet number value to the buffer
    std::memcpy(data.data() + offset, &packet_number, sizeof(packet_number));
    offset += sizeof(packet_number);

	// Copy the total packets value to the buffer
    std::memcpy(data.data() + offset, &total_packets, sizeof(total_packets));
    offset += sizeof(total_packets);

	// Copy the file name to the buffer
    std::memcpy(data.data() + offset, file_name.data(), FILE_NAME_SIZE);
    offset += FILE_NAME_SIZE;

	// Copy the encrypted content to the buffer
    std::memcpy(data.data() + offset, encrypted_content.data(), encrypted_content.size());
    return data;
}
#pragma endregion

#pragma region CrcValidPayload
CrcValidPayload::CrcValidPayload(const std::string& file_name) {
    if (file_name.length() >= FILE_NAME_SIZE) { // Check if the name is too long which means that the padding won't fit
        throw std::invalid_argument("File name is too long");
    }
    this->file_name = file_name;
	this->file_name.resize(FILE_NAME_SIZE); // Resize the file name to the expected size
     
}

CrcValidPayload& CrcValidPayload::operator=(const CrcValidPayload& other) {
    if (this != &other) {
        file_name = other.file_name;
        
    }
    return *this;
}

std::vector<uint8_t> CrcValidPayload::pack() const{
    std::vector<uint8_t> data(FILE_NAME_SIZE);
	std::memcpy(data.data(), file_name.data(), FILE_NAME_SIZE); // Copy the file name
    return data;
}
#pragma endregion

#pragma region CrcInvalidPayload
CrcInvalidPayload::CrcInvalidPayload(const std::string& file_name) {
    if (file_name.length() >= FILE_NAME_SIZE) { // Check if the name is too long which means that the padding won't fit
        throw std::invalid_argument("File name is too long");
    }
    this->file_name = file_name;
	this->file_name.resize(FILE_NAME_SIZE); // Resize the file name to the expected size
    
}

CrcInvalidPayload& CrcInvalidPayload::operator=(const CrcInvalidPayload& other) {
    if (this != &other) {
        file_name = other.file_name;
        
    }
    return *this;
}

std::vector<uint8_t> CrcInvalidPayload::pack() const {
    std::vector<uint8_t> data(FILE_NAME_SIZE);
	std::memcpy(data.data(), file_name.data(), FILE_NAME_SIZE); // Copy the file name
    return data;
}
#pragma endregion

#pragma region CrcInvalidInFourthTimePayload
CrcInvalidInFourthTimePayload::CrcInvalidInFourthTimePayload(const std::string& file_name) {
    if (file_name.length() >= FILE_NAME_SIZE) { // Check if the name is too long which means that the padding won't fit
        throw std::invalid_argument("File name is too long");
    }
	this->file_name = file_name;
	this->file_name.resize(FILE_NAME_SIZE); // Resize the file name to the expected size
    
}

CrcInvalidInFourthTimePayload& CrcInvalidInFourthTimePayload::operator=(const CrcInvalidInFourthTimePayload& other) {
    if (this != &other) {
        file_name = other.file_name;
        
    }
    return *this;
}

std::vector<uint8_t> CrcInvalidInFourthTimePayload::pack() const {
    std::vector<uint8_t> data(FILE_NAME_SIZE);
	std::memcpy(data.data(), file_name.data(), FILE_NAME_SIZE); // Copy the file name
    return data;
}
#pragma endregion


#pragma region RegisterSuccessedPayload

RegisterSuccessedPayload::RegisterSuccessedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& id) {
    client_id = id;
}

RegisterSuccessedPayload& RegisterSuccessedPayload::operator=(const RegisterSuccessedPayload& other) {
    if (this != &other) {
        client_id = other.client_id;
    }
    return *this;
}

RegisterSuccessedPayload RegisterSuccessedPayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
	std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE); // Copy the client ID
	return RegisterSuccessedPayload(client_id);
}
#pragma endregion


#pragma region ReceivedEncryptedAesKeyPayload
ReceivedEncryptedAesKeyPayload::ReceivedEncryptedAesKeyPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, const std::string& aes_key_encrypted) {
    this->client_id = client_id;
    this->aes_encrypted_key = aes_key_encrypted;
}

ReceivedEncryptedAesKeyPayload& ReceivedEncryptedAesKeyPayload::operator=(const ReceivedEncryptedAesKeyPayload& other) {
    if (this != &other) {
        client_id = other.client_id;
        aes_encrypted_key = other.aes_encrypted_key; 
    }
    return *this;
}

ReceivedEncryptedAesKeyPayload ReceivedEncryptedAesKeyPayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
    std::string aes_key_encrypted;
     
	std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE); // Copy the client ID
	aes_key_encrypted.assign(data.begin() + CLIENT_ID_SIZE, data.end()); // Copy the encrypted AES key

    return ReceivedEncryptedAesKeyPayload(client_id, aes_key_encrypted);
}
#pragma endregion

#pragma region FileReceivedPayload
FileReceivedPayload::FileReceivedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, uint16_t content_size, const std::string& file_name, uint32_t checksum) {
    this->client_id = client_id;
    this->content_size = content_size;
    this->file_name = file_name;
    this->checksum = checksum;
}

FileReceivedPayload& FileReceivedPayload::operator=(const FileReceivedPayload& other) {
    if (this != &other) {
        client_id = other.client_id;
        content_size = other.content_size;
        file_name = other.file_name;
        checksum = other.checksum;
    }
    return *this;
}

FileReceivedPayload FileReceivedPayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
    uint32_t content_size;
    std::string file_name;
    uint32_t checksum;

    // Resize file_name to the expected size
    file_name.resize(FILE_NAME_SIZE);

    // Copy client ID
    std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE);

    // Copy content size
    std::memcpy(&content_size, data.data() + CLIENT_ID_SIZE, sizeof(content_size));

    // Copy file name
    file_name.assign(data.begin() + CLIENT_ID_SIZE + sizeof(content_size),
        data.begin() + CLIENT_ID_SIZE + sizeof(content_size) + FILE_NAME_SIZE);

    // Copy checksum
    std::memcpy(&checksum, data.data() + CLIENT_ID_SIZE + sizeof(content_size) + FILE_NAME_SIZE, sizeof(checksum));

    return FileReceivedPayload(client_id, content_size, file_name, checksum);
}
#pragma endregion

#pragma region AcceptMessagePayload
AcceptMessagePayload::AcceptMessagePayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id) {
    this->client_id = client_id;
}

AcceptMessagePayload& AcceptMessagePayload::operator=(const AcceptMessagePayload& other) {
    if (this != &other) {
        client_id = other.client_id;
    }
    return *this;
}

AcceptMessagePayload AcceptMessagePayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
	std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE); // Copy the client ID
    return AcceptMessagePayload(client_id);
}
#pragma endregion

#pragma region ReconnectRequestAcceptedPayload
ReconnectRequestAcceptedPayload::ReconnectRequestAcceptedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id, const std::string& aes_encrypted_key) {
    this->client_id = client_id;
    this->aes_encrypted_key = aes_encrypted_key;
}

ReconnectRequestAcceptedPayload& ReconnectRequestAcceptedPayload::operator=(const ReconnectRequestAcceptedPayload& other) {
    if (this != &other) {
        client_id = other.client_id;
        aes_encrypted_key = other.aes_encrypted_key;
    }
    return *this;
}

ReconnectRequestAcceptedPayload ReconnectRequestAcceptedPayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
    std::string aes_encrypted_key;

	std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE); // Copy the client ID
	aes_encrypted_key.assign(data.begin() + CLIENT_ID_SIZE, data.end()); // Copy the encrypted AES key

	return ReconnectRequestAcceptedPayload(client_id, aes_encrypted_key); // Create the object and return it
}
#pragma endregion

#pragma region ReconnectRequestRejectedPayload
ReconnectRequestRejectedPayload::ReconnectRequestRejectedPayload(const std::array<uint8_t, CLIENT_ID_SIZE>& client_id) {
	this->client_id = client_id; // Copy the client ID
}

ReconnectRequestRejectedPayload& ReconnectRequestRejectedPayload::operator=(const ReconnectRequestRejectedPayload& other) {
    if (this != &other) {
        client_id = other.client_id;
    }
    return *this;
}

ReconnectRequestRejectedPayload ReconnectRequestRejectedPayload::unpack(std::vector<uint8_t>& data) {
    std::array<uint8_t, CLIENT_ID_SIZE> client_id;
	std::memcpy(client_id.data(), data.data(), CLIENT_ID_SIZE); // Copy the client ID
	return ReconnectRequestRejectedPayload(client_id); // Create the object and return it
}
#pragma endregion