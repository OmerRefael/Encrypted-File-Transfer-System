#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <utility>   
#include "bytes_utils.h"

std::string hexify(const unsigned char* buffer, size_t length) {
	std::ostringstream oss; // The output string stream
    oss << std::hex << std::setfill('0');

	for (unsigned int i = 0; i < length; ++i) { // Iterate through the buffer
		oss << std::setw(2) << static_cast<int>(buffer[i]); // Convert the byte to a hex string
    }
	return oss.str(); // Return the hex string
}


std::vector<uint8_t> unhexed(const std::string& hex) {
	if (hex.length() % 2 != 0) { // Check if the hex string has an even length
        throw std::invalid_argument("Hex string must have an even length");
    }

    std::vector<unsigned char> result;
    result.reserve(hex.length() / 2);

	for (size_t i = 0; i < hex.length(); i += 2) { // Iterate through the hex string
		unsigned char byte = static_cast<unsigned char>(std::stoul(hex.substr(i, 2), nullptr, 16)); // Convert the hex string to a byte
        result.push_back(byte);
    }
    return result;
}


void swap_bytes(uint8_t* data, size_t size) {
	for (size_t i = 0; i < size / 2; ++i) {  // Iterate through half of the data
		std::swap(data[i], data[size - 1 - i]); // Swap the bytes
    }
}