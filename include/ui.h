#ifndef UI_H
#define UI_H

#include <iostream>
#include <string>

// ANSI colors (works on most terminals; safe-ish fallback if unsupported)
constexpr const char *RESET = "\x1b[0m";
constexpr const char *BOLD = "\x1b[1m";
constexpr const char *DIM = "\x1b[2m";
constexpr const char *RED = "\x1b[31m";
constexpr const char *GREEN = "\x1b[32m";
constexpr const char *YELLOW = "\x1b[33m";
constexpr const char *CYAN = "\x1b[36m";

inline void header(int step, int total, const std::string &title) {
  std::cout << "\n"
            << BOLD << CYAN << "==[ STEP " << step << "/" << total
            << " ]== " << title << RESET << "\n";
}

inline void ok(const std::string &msg) {
  std::cout << GREEN << "[ OK ] " << RESET << msg << "\n";
}

inline void warn(const std::string &msg) {
  std::cout << YELLOW << "[WARN] " << RESET << msg << "\n";
}

inline void fail(const std::string &msg) {
  std::cout << RED << "[FAIL] " << RESET << msg << "\n";
}

inline void kv(const std::string &k, const std::string &v) {
  std::cout << "  " << DIM << k << RESET << ": " << v << "\n";
}

#endif // UI_H
