#include "general_utils.h"

void fatal_error(const std::string& message, int line, Logger& logger) {
	std::string final_message = "Fatal error: " + message + "\n" + "Exiting..."; // The fatal error message
	logger.log(Logger::Level::PROBLEM, final_message, line);
}