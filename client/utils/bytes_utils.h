#ifndef BYTES_UTILS_H
#define BYTES_UTILS_H

#include <string>
#include <vector>

/**
 * Converts a buffer to a hex string. 
 * 
 * Parameters:
 *     buffer: The buffer to convert.
 *     length: The length of the buffer.
 * 
 * Returns:
 *     The hex string representation of the buffer.
 */
std::string hexify(const unsigned char* buffer, size_t length);
/**
 * Converts a hex string to a vector of bytes.
 * 
 * Parameters:
 *     hex: The hex string to convert to bytes.
 * 
 * Returns:
 *     The vector of bytes that was represented by the hex string.
 */
std::vector<uint8_t> unhexed(const std::string& hex);
/**
 * Swaps the bytes of the data.
 * This function is useful for converting between big-endian and little-endian.
 * 
 * Parameters:
 *     data: The data to swap the bytes of.
 *     size: The size of the data.
 */
void swap_bytes(uint8_t* data, size_t size);

#endif