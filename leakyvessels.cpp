/*
Author:  c0d3Ninja
Website: https://gotr00t0day.github.com

This tool checks whether the host’s runc version is in the range affected by CVE-2024-21626 (“Leaky Vessels”). 

*/

#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <array>
#include <sstream>
#include <filesystem>

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"
#define BOLD    "\033[1m"
#define UNDERLINE "\033[4m"

bool findRunc() {
    std::vector<std::string> runcPath = {"/usr/bin/runc", "/usr/local/sbin/runc", "/usr/sbin/runc"};
    for (const auto& rP : runcPath) {
        if(std::filesystem::exists(rP)) {
            return true;
        }
    }
    int cmd = system("which runc > /dev/null 2>&1");
    if (cmd == 0) {
        return true;
    }
    return false;
 }

std::vector<int> parse_version(const std::string& v) {
    std::vector<int> parts;
    std::stringstream ss(v);
    std::string item;

    while (std::getline(ss, item, '.')) {
        parts.push_back(std::stoi(item));
    }
    return parts;
}

bool is_vulnerable(const std::string& version) {
    std::vector<int> v = parse_version(version);
    std::vector<int> max = {1, 1, 11};

    for (size_t i = 0; i < max.size(); ++i) {
        if (v[i] < max[i]) return true;
        if (v[i] > max[i]) return false;
    }
    return true;
}

std::string get_runc_version() {
    std::array<char, 128> buffer;
    std::string result;

    FILE* pipe = popen("runc --version 2>/dev/null", "r");
    if (!pipe) return "";

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }

    pclose(pipe);

    size_t pos = result.find("version ");
    if (pos == std::string::npos) return "";

    return result.substr(pos + 8, result.find('\n') - (pos + 8));
}

int main() {
    std::cout << CYAN << R"(
██      ███████  █████  ██   ██ ██    ██     ██    ██ ███████ ███████ ███████ ███████ ██      ███████ 
██      ██      ██   ██ ██  ██   ██  ██      ██    ██ ██      ██      ██      ██      ██      ██      
██      █████   ███████ █████     ████       ██    ██ █████   ███████ ███████ █████   ██      ███████ 
██      ██      ██   ██ ██  ██     ██         ██  ██  ██           ██      ██ ██      ██           ██ 
███████ ███████ ██   ██ ██   ██    ██          ████   ███████ ███████ ███████ ███████ ███████ ███████   

          CVE-2024-21626  (Leaky Vessels / runc)
)" << RESET << "\n";
    std::cout << "Checking for CVE-2024-21626.." << "\n";
    if (findRunc()) {
        std::string v = get_runc_version();
        std::cout << "Found: " << "runc " << v << "\n";
        if (!v.empty() && is_vulnerable(v)) {
            std::cout << RED << v << " Vulnerable to Leaky Vessels" << "\n";
        }
    } else {
        std::cout << YELLOW << "runc not found!" << "\n";
    }
    return 0;
}
