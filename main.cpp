
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "config.cpp"
#include "logging.cpp"
#include "minhook/include/MinHook.h"
#include "proxy_exports.cpp"

#include <algorithm>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <unordered_map>
#include <cstddef>
#include <processthreadsapi.h>
#include <sysinfoapi.h>
#include <vector>
#include <winnt.h>


#pragma comment(lib, "wintrust.lib")

static HMODULE g_dllModule = nullptr;
static Logger g_logger("hooker.log");
static ConfigParser g_configParser;
static Config g_config;

typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCSTR);
typedef HMODULE(WINAPI *LoadLibraryW_t)(LPCWSTR);
typedef HMODULE(WINAPI *LoadLibraryExA_t)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI *LoadLibraryExW_t)(LPCWSTR, HANDLE, DWORD);
typedef LONG(WINAPI *WinVerifyTrust_t)(HWND, GUID *, LPVOID);

static LoadLibraryA_t fpLoadLibraryA = nullptr;
static LoadLibraryW_t fpLoadLibraryW = nullptr;
static LoadLibraryExA_t fpLoadLibraryExA = nullptr;
static LoadLibraryExW_t fpLoadLibraryExW = nullptr;
static WinVerifyTrust_t fpWinVerifyTrust = nullptr;
static int g_wintrustHook_Count = 0;

static std::unordered_map<FARPROC, FARPROC> g_exportRedirects;
static HMODULE g_originalDll = nullptr;
static HMODULE g_replacementDll = nullptr;

bool IsTargetDll(const char *path) {
	if (!path || g_config.targetDll.empty())
		return false;

	std::string filename(path);
	size_t lastSlash = filename.find_last_of("\\/");
	if (lastSlash != std::string::npos) {
		filename = filename.substr(lastSlash + 1);
	}

	std::string target = g_config.targetDll;
	std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
	std::transform(target.begin(), target.end(), target.begin(), ::tolower);

	return filename == target;
}

bool IsTargetDllW(const wchar_t *path) {
	if (!path || g_config.targetDll.empty())
		return false;

	std::wstring filename(path);
	size_t lastSlash = filename.find_last_of(L"\\/");
	if (lastSlash != std::string::npos) {
		filename = filename.substr(lastSlash + 1);
	}

	std::wstring target;
	for (const char c : g_config.targetDll) {
		target += static_cast<wchar_t>(c);
	}

	std::transform(filename.begin(), filename.end(), filename.begin(),
								 ::towlower);
	std::transform(target.begin(), target.end(), target.begin(), ::towlower);

	return filename == target;
}

static bool IsExecutableAddress(LPVOID address) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) {
		return false;
	}
	return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
												 PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

bool RedirectExports(HMODULE originalModule, HMODULE replacementModule) {
	std::vector<std::string> ignoreExports;
	std::string exportName;
	std::istringstream f(g_config.ignoreExports);
	while (std::getline(f, exportName, ',')) {
		ignoreExports.push_back(exportName);
	}
	
	if (!originalModule || !replacementModule)
		return false;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)originalModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		g_logger.log(ERR, "Invalid DOS header");
		return false;
	}

	PIMAGE_NT_HEADERS ntHeaders =
			(PIMAGE_NT_HEADERS)((BYTE *)originalModule + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		g_logger.log(ERR, "Invalid NT header");
		return false;
	}

	DWORD exportDirRVA =
			ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
					.VirtualAddress;
	DWORD exportDirSize =
			ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
					.Size;
	if (exportDirRVA == 0) {
		g_logger.log(ERR, "No export directory found");
		return false;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir =
			(PIMAGE_EXPORT_DIRECTORY)((BYTE *)originalModule + exportDirRVA);

	DWORD *nameRVAs =
			(DWORD *)((BYTE *)originalModule + exportDir->AddressOfNames);
	WORD *ordinals =
			(WORD *)((BYTE *)originalModule + exportDir->AddressOfNameOrdinals);
	DWORD *funcRVAs =
			(DWORD *)((BYTE *)originalModule + exportDir->AddressOfFunctions);

	g_logger.log(INFO, "Found %d named exports", exportDir->NumberOfNames);

	int hooked = 0;
	int skippedData = 0;
	int skippedForwarded = 0;

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
		const char *funcName = (const char *)((BYTE *)originalModule + nameRVAs[i]);
		WORD ordinal = ordinals[i];
		DWORD funcRVA = funcRVAs[ordinal];

		if (std::find(ignoreExports.begin(), ignoreExports.end(), funcName) != ignoreExports.end()) {
			g_logger.log(INFO, "Skipping ignored export: %s", funcName);
			continue;
		}

		if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize) {
			const char *forwardName =
					(const char *)((BYTE *)originalModule + funcRVA);
			g_logger.log(INFO, "Skipping forwarded export: %s -> %s", funcName,
									 forwardName);
			skippedForwarded++;
			continue;
		}

		FARPROC originalFunc = (FARPROC)((BYTE *)originalModule + funcRVA);

		if (!IsExecutableAddress((LPVOID)originalFunc)) {
			g_logger.log(INFO, "Skipping data export: %s (not executable)", funcName);
			skippedData++;
			continue;
		}

		FARPROC replacementFunc = GetProcAddress(replacementModule, funcName);

		if (replacementFunc) {
			if (g_exportRedirects.find(originalFunc) != g_exportRedirects.end()) {
				continue;
			}

			MH_STATUS status =
					MH_CreateHook((LPVOID)originalFunc, (LPVOID)replacementFunc, nullptr);
			if (status == MH_OK) {
				MH_EnableHook((LPVOID)originalFunc);
				g_exportRedirects[originalFunc] = replacementFunc;
				hooked++;
				g_logger.log(INFO, "Hooked export: %s", funcName);
			} else {
				g_logger.log(WARN, "Failed to hook %s: %s", funcName,
										 MH_StatusToString(status));
			}
		} else {
			g_logger.log(INFO, "Export %s not found in replacement DLL", funcName);
		}
	}

	g_logger.log(
			INFO, "Successfully hooked %d/%d exports (skipped %d data, %d forwarded)",
			hooked, exportDir->NumberOfNames, skippedData, skippedForwarded);
	return hooked > 0;
}

HMODULE ProcessTargetDll(HMODULE original) {
	if (!original) {
		g_logger.log(ERR, "Failed to load target DLL");
		return nullptr;
	}

	if (g_config.replaceDll.empty()) {
		g_logger.log(ERR, "No replacement DLL specified in config");
		return original;
	}

	HMODULE replacement = fpLoadLibraryA(g_config.replaceDll.c_str());
	if (!replacement) {
		g_logger.log(ERR, "Failed to load replacement DLL: %s",
								 g_config.replaceDll.c_str());
		return original;
	}

	g_originalDll = original;
	g_replacementDll = replacement;

	RedirectExports(original, replacement);

	return original;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
	if (g_config.dllEnable && IsTargetDll(lpLibFileName)) {
		HMODULE original = fpLoadLibraryA(lpLibFileName);
		if (original) {
			g_logger.log(INFO, "Loaded dll: %s", lpLibFileName);
		}
		return ProcessTargetDll(original);
	}
	return fpLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
	if (g_config.dllEnable && IsTargetDllW(lpLibFileName)) {
		HMODULE original = fpLoadLibraryW(lpLibFileName);
		if (original) {
			g_logger.log(INFO, "Loaded dll: %ls", lpLibFileName);
		}
		return ProcessTargetDll(original);
	}
	return fpLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile,
																		DWORD dwFlags) {
	if (g_config.dllEnable && IsTargetDll(lpLibFileName)) {
		HMODULE original = fpLoadLibraryExA(lpLibFileName, hFile, dwFlags);
		if (original) {
			g_logger.log(INFO, "Loaded dll: %s", lpLibFileName);
		}
		return ProcessTargetDll(original);
	}
	return fpLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile,
																		DWORD dwFlags) {
	if (g_config.dllEnable && IsTargetDllW(lpLibFileName)) {
		HMODULE original = fpLoadLibraryExW(lpLibFileName, hFile, dwFlags);
		if (original) {
			g_logger.log(INFO, "Loaded dll: %ls", lpLibFileName);
		}
		return ProcessTargetDll(original);
	}
	return fpLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

LONG WINAPI HookedWinVerifyTrust(HWND hwnd, GUID *pgActionID, LPVOID pWVTData) {
	if (g_wintrustHook_Count == 0) {
		g_logger.log(INFO, "WinVerifyTrust intercepted - returning trusted");
		g_wintrustHook_Count++;
	}
	return 0;
}

bool InitializeHooks() {
	MH_STATUS status = MH_Initialize();
	if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
		g_logger.log(ERR, "MH_Initialize failed: %s", MH_StatusToString(status));
		return false;
	}

	if (g_config.dllEnable) {
		if (MH_CreateHookApi(L"kernel32", "LoadLibraryA",
												 (LPVOID)HookedLoadLibraryA,
												 (LPVOID *)&fpLoadLibraryA) != MH_OK) {
			g_logger.log(ERR, "Failed to hook LoadLibraryA");
			return false;
		}

		if (MH_CreateHookApi(L"kernel32", "LoadLibraryW",
												 (LPVOID)HookedLoadLibraryW,
												 (LPVOID *)&fpLoadLibraryW) != MH_OK) {
			g_logger.log(ERR, "Failed to hook LoadLibraryW");
			return false;
		}

		if (MH_CreateHookApi(L"kernel32", "LoadLibraryExA",
												 (LPVOID)HookedLoadLibraryExA,
												 (LPVOID *)&fpLoadLibraryExA) != MH_OK) {
			g_logger.log(ERR, "Failed to hook LoadLibraryExA");
			return false;
		}

		if (MH_CreateHookApi(L"kernel32", "LoadLibraryExW",
												 (LPVOID)HookedLoadLibraryExW,
												 (LPVOID *)&fpLoadLibraryExW) != MH_OK) {
			g_logger.log(ERR, "Failed to hook LoadLibraryExW");
			return false;
		}

		g_logger.log(INFO, "LoadLibrary hooks installed - watching for: %s",
								 g_config.targetDll.c_str());
	}

	if (g_config.wintrustHook) {
		if (MH_CreateHookApi(L"wintrust", "WinVerifyTrust",
												 (LPVOID)HookedWinVerifyTrust,
												 (LPVOID *)&fpWinVerifyTrust) != MH_OK) {
			g_logger.log(ERR, "Failed to hook WinVerifyTrust");
		} else {
			g_logger.log(INFO, "WinVerifyTrust hook installed");
		}
	}

	if (g_config.coreCount >= 0) {
		int error = 0;
		g_logger.log(INFO, "Set LIMIT_CORE_COUNT to %d", g_config.coreCount);
		g_logger.log(INFO, "-> Ignoring E-Cores ? %d", g_config.ignoreEcores);

		DWORD len = 0;
		GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			g_logger.log(ERR, "Failed to get processor information size");
			error = 1;
		}

		std::vector<char> buffer(len);
		auto *info =
				reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *>(buffer.data());
		if (!GetLogicalProcessorInformationEx(RelationProcessorCore, info, &len)) {
			g_logger.log(ERR, "Failed to get processor information");
			error = 1;
		}

		if (!error){
			DWORD_PTR mask = 0;
			unsigned int used = 0;
			char* ptr = buffer.data();
			char* end = buffer.data() + len;

			while (ptr < end && used < (unsigned int)g_config.coreCount) {
				auto* core = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(ptr);
				
				bool skipCore = g_config.ignoreEcores && (core->Processor.EfficiencyClass != 0);
				if (!skipCore) {
					KAFFINITY coreMask = core->Processor.GroupMask[0].Mask;

					mask |= coreMask;
					++used;
				}

				g_logger.log(INFO, "Core: EfficiencyClass=%d, Mask=0x%llX", 
					core->Processor.EfficiencyClass, 
					(unsigned long long)core->Processor.GroupMask[0].Mask);

				ptr += core->Size;
			}

			g_logger.log(INFO, "Setting process affinity mask to 0x%llX", (unsigned long long)mask);
			if (!SetProcessAffinityMask(GetCurrentProcess(), mask)) {
				g_logger.log(ERR, "Failed to set process affinity mask");
			}
		}
		
	}

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		g_logger.log(ERR, "Failed to enable hooks");
		return false;
	}

	return true;
}

void CheckAlreadyLoadedTargetDll() {
	if (!g_config.dllEnable || g_config.targetDll.empty()) {
		return;
	}

	HMODULE existing = GetModuleHandleA(g_config.targetDll.c_str());
	if (existing) {
		g_logger.log(INFO, "Target DLL %s already loaded at (0x%p)",
								 g_config.targetDll.c_str(), existing);
		ProcessTargetDll(existing);
		return;
	}

	HANDLE snapshot =
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (snapshot == INVALID_HANDLE_VALUE) {
		g_logger.log(WARN, "Failed to create module snapshot");
		return;
	}

	MODULEENTRY32 me;
	me.dwSize = sizeof(me);

	if (Module32First(snapshot, &me)) {
		do {
			if (IsTargetDll(me.szExePath)) {
				g_logger.log(INFO, "Found target DLL %s at 0x%p", me.szExePath,
										 me.hModule);
				ProcessTargetDll(me.hModule);
				break;
			}
		} while (Module32Next(snapshot, &me));
	}

	CloseHandle(snapshot);
}

void Cleanup() {
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
	(void)reserved;

	switch (reason) {
	case DLL_PROCESS_ATTACH:
		g_dllModule = hModule;
		DisableThreadLibraryCalls(hModule);

		g_configParser.load();
		g_config = g_configParser.getConfig();

		g_logger.log(INFO, "Config loaded from: %s",
								 g_configParser.getIniPath().c_str());
		g_logger.log(INFO, "DLL Enable: %d, Target: %s, Replace: %s",
								 g_config.dllEnable, g_config.targetDll.c_str(),
								 g_config.replaceDll.c_str());
		g_logger.log(INFO, "WinTrust Hook: %d", g_config.wintrustHook);

		if (InitializeHooks()) {
			g_logger.log(INFO, "Hooks installed successfully");
			CheckAlreadyLoadedTargetDll();
		} else {
			g_logger.log(ERR, "Failed to initialize hooks");
		}
		break;

	case DLL_PROCESS_DETACH:
		Cleanup();
		FreeRealDll();
		g_logger.log(INFO, "DLL unloaded");
		break;

	default:
		break;
	}
	return TRUE;
}