#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

#include <string>
#include <array>
#include "../cryptopp/RSAWrapper.h"


/**
 * Encrypts the data using the AES key.
 * 
 * Parameters:
 *     data: The data to encrypt.
 */
std::string encrypt_data_by_aes_key(const std::string& content, const std::string& aes_key);
/**
 * Decrypts the data using the AES key.
 * 
 * Parameters:
 *     data: The data to decrypt.
 */
std::string decrypt_data_by_private_key(const std::string& base64_private_key, const std::string& data);
/**
 * Generates a pair of RSA keys. The public key is stored in the public_key array, and the private key is stored in base64_private_key.
 * 
 * Parameters:
 *     public_key: The array to store the public key.
 *     base64_private_key: The string to store the base64-encoded private key.
 * 
 */
void generate_keys(std::array<uint8_t, RSAPublicWrapper::KEYSIZE>& public_key, std::string& base64_private_key);

#endif // ENCRYPTION_UTILS_H