#ifndef LOGGER_H
#define LOGGER_H

#include <string>

namespace Logger {

	void LogMessage(const std::string& message);

	void Cleanup();
}


#endif // !LOGGER_H
