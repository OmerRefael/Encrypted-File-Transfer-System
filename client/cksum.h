#ifndef CKSUM_H
#define CKSUM_H

#include <string>
#include <cstdint>

/*
 * This function calculates the checksum of a file.
 *
 * Parameters:
 *     fname: The name of the file to calculate the checksum.
 *
 * Returns:
 *     The checksum of the file.
 */
uint32_t calculate_file_checksum(const std::string& fname);

#endif