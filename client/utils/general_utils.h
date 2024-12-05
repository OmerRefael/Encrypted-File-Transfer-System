#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <string>
#include "..\logger.h"

/**
 * Logs a fatal error message and exits the program.
 * 
 * Parameters:
 *     message: The message to log.
 *     line: The line number of the log message.
 *     logger: The logger to log the message with.
 */
void fatal_error(const std::string& message, int line, Logger& logger);


#endif // GENERAL_UTILS_H