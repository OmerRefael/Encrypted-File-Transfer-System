#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <chrono>
#include <ctime>
#include <string>

/**
* This class is responsible for logging messages to the console.
*
* This class supports logging messages at different severity levels, and
* can be configured to only log messages above a specified minimum level.
*/
class Logger {
public:

    /**
    * Enum of the different levels of logging.
    * DEBUG: Debugging messages.
    * INFO: Informational messages.
    * WARNING: Warning messages.
    * PROBLEM: Error messages.
    */
    enum class Level {
        DEBUG,
        INFO,
        WARNING,
        PROBLEM
    };

    /**
    * The constructor of the Logger class.
    * 
    * Parameters:
    *     path: The path of the file that the log message came from (and extract the name of the file from it).
    */
    Logger(const char* path);
    /** 
     * This function logs a message at the specified level, just if the level is greater than or equal to the minimum level.
     * 
     * Parameters:
     *     level: The level of the log message.
     *     message: The message to log.
     *     line: The line number of the log message.
    */
    void log(Level level, const std::string& message, int line);
    /**
     * This function sets the minimum level of logging.
     * 
     * Parameters:
     *     level: The minimum level of logging.
     */
    void set_min_level(Level level);

private:
    Level min_level = Level::INFO; // The minimum level of logging (initially set to INFO).
    std::string file_name;

    /**
     * This function returns the current time for the log message.
     * 
     * Returns:
     *     The current time in a string format.
     */
    std::string getCurrentTime();
    /**
     * This function returns the color of the log message based on the level.
     * 
     * Parameters:
     *     level: The level of the log message.
     * 
     * Returns:
     *     The color of the log message.
     */
    std::string getColor(Level level);
};

#endif // LOGGER_H
