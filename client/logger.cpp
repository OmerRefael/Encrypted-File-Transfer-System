#include "logger.h"
#include "file_handler.h"

Logger::Logger(const char* path){
	this->file_name = extract_file_name_from_path(path); // Get the file name from the path
}

std::string Logger::getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);

    char buffer[100]; // Buffer for ctime_s
    ctime_s(buffer, sizeof(buffer), &now_time); // Use ctime_s for safety
    std::string time_str(buffer);
    time_str.pop_back(); // Remove newline character
    return time_str;
}

std::string Logger::getColor(Level level) {
	switch (level) { // Return ANSI escape code for color
	case Level::DEBUG: return "\033[34m"; // Blue
    case Level::INFO: return "\033[32m"; // Green
    case Level::WARNING: return "\033[33m"; // Yellow
    case Level::PROBLEM: return "\033[31m"; // Red
    default: return "\033[0m"; // Reset
    }
}

void Logger::log(Level level, const std::string& message, int line) {
	if (level < min_level) return; // Check if the level is above the minimum level

	static const char* level_names[] = { "DEBUG", "INFO", "WARNING", "ERROR" }; // Array of level names

    std::cout << getColor(level) << "[" << getCurrentTime() << "] "
        << level_names[static_cast<int>(level)] << ": "
        << message << " (File: " << file_name << ", Line: " << line << ")"
        << "\033[0m" << std::endl; // Reset color
}

void Logger::set_min_level(Level level) { // Set the minimum level
    min_level = level;
}