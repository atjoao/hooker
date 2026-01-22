#pragma once
#include <cstdlib>
#include <string>
#include <windows.h>

struct Config {
  // [DLL] section
  bool dllEnable;
  std::string targetDll;
  std::string replaceDll;

  // [ADC] section
  bool wintrustHook;

  Config() : dllEnable(false), wintrustHook(false) {}
};

class ConfigParser {
private:
  std::string m_iniPath;
  Config m_config;

  std::string getIniString(const char *section, const char *key,
                           const char *defaultValue) {
    char buffer[MAX_PATH];
    GetPrivateProfileStringA(section, key, defaultValue, buffer, MAX_PATH,
                             m_iniPath.c_str());
    return std::string(buffer);
  }

  int getIniInt(const char *section, const char *key, int defaultValue) {
    return GetPrivateProfileIntA(section, key, defaultValue, m_iniPath.c_str());
  }

public:
  ConfigParser() {
    // Get the path to the INI file (same directory as the DLL)
    char dllPath[MAX_PATH];
    HMODULE hModule = nullptr;
    // Use a static variable's address (member function pointers can't be cast
    // to LPCSTR)
    static int dummy = 0;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&dummy, &hModule);
    GetModuleFileNameA(hModule, dllPath, MAX_PATH);

    // Replace DLL filename with hooker.ini
    std::string path(dllPath);
    size_t lastSlash = path.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
      path = path.substr(0, lastSlash + 1);
    }
    m_iniPath = path + "hooker.ini";
  }

  bool load() {
    // Check if file exists
    DWORD attrib = GetFileAttributesA(m_iniPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
      // Create default config file
      createDefaultConfig();
      return false;
    }

    // [DLL] section
    m_config.dllEnable = getIniInt("DLL", "enable", 0) != 0;
    m_config.targetDll = getIniString("DLL", "target", "");
    m_config.replaceDll = getIniString("DLL", "replace", "");

    // [ADC] section
    m_config.wintrustHook = getIniInt("ADC", "wintrust", 0) != 0;

    return true;
  }

  void createDefaultConfig() {
    WritePrivateProfileStringA("DLL", "enable", "0", m_iniPath.c_str());
    WritePrivateProfileStringA("DLL", "target", "", m_iniPath.c_str());
    WritePrivateProfileStringA("DLL", "replace", "", m_iniPath.c_str());
    WritePrivateProfileStringA("ADC", "wintrust", "0", m_iniPath.c_str());
    MessageBoxA(nullptr,
                "Config file (hooker.ini) not found, created default config",
                "Hooker", MB_OK);
    exit(0);
  }

  const Config &getConfig() const { return m_config; }
  const std::string &getIniPath() const { return m_iniPath; }
};
