#include <string>
#include <array>
#include <stdexcept>
#include <cstring>
#include "encryption_utils.h"
#include "../cryptopp/Base64Wrapper.h"
#include "../cryptopp/RSAWrapper.h"
#include "../cryptopp/AESWrapper.h"



std::string encrypt_data_by_aes_key(const std::string& data, const std::string& aes_key) {
    AESWrapper aes(reinterpret_cast<const unsigned char*>(aes_key.data()), AESWrapper::DEFAULT_KEYLENGTH);
	return aes.encrypt(data.c_str(), static_cast<unsigned int>(data.size()));
}


std::string decrypt_data_by_private_key(const std::string& base64_private_key, const std::string& encrypted_data) {
    try {
		RSAPrivateWrapper rsapriv(Base64Wrapper::decode(base64_private_key));
		return rsapriv.decrypt(encrypted_data);
	}
    catch (...) {
		throw std::runtime_error("Incorrect private key");
    }

}


void generate_keys(std::array<uint8_t, RSAPublicWrapper::KEYSIZE>& public_key, std::string& base64_private_key) {
    RSAPrivateWrapper rsapriv;
    char pubkey_buff[RSAPublicWrapper::KEYSIZE];
	rsapriv.getPublicKey(pubkey_buff, RSAPublicWrapper::KEYSIZE); // Get the public key
    std::memcpy(public_key.data(), pubkey_buff, RSAPublicWrapper::KEYSIZE);
	base64_private_key = Base64Wrapper::encode(rsapriv.getPrivateKey()); // Get the private key
}