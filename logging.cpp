#pragma once
#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <string>

enum LogLevel { DEBUG, INFO, WARN, ERR };

class Logger {
private:
  FILE *m_file;
  std::string m_filename;
  bool m_enabled;

  const char *levelToString(LogLevel level) {
    switch (level) {
    case DEBUG:
      return "DEBUG";
    case INFO:
      return "INFO";
    case WARN:
      return "WARN";
    case ERR:
      return "ERROR";
    default:
      return "UNKNOWN";
    }
  }

public:
  Logger(const char *filename)
      : m_file(nullptr), m_filename(filename), m_enabled(true) {
    m_file = fopen(filename, "w+");
  }

  ~Logger() {
    if (m_file) {
      fclose(m_file);
      m_file = nullptr;
    }
  }

  void setEnabled(bool enabled) { m_enabled = enabled; }

  void log(LogLevel level, const char *format, ...) {
    if (!m_enabled || !m_file)
      return;

    // Get current time
    time_t now = time(nullptr);
    struct tm *timeinfo = localtime(&now);
    char timeStr[32];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Write timestamp and level
    fprintf(m_file, "[%s] [%s] ", timeStr, levelToString(level));

    // Write formatted message
    va_list args;
    va_start(args, format);
    vfprintf(m_file, format, args);
    va_end(args);

    fprintf(m_file, "\n");
    fflush(m_file);
  }
};
