#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <tlhelp32.h>

// Taken from https://cplusplus.com/forum/general/243349/
std::string wStringToString(const std::wstring& wstr) {
    static std::wstring_convert< std::codecvt_utf8<wchar_t>, wchar_t > converter;
    return converter.to_bytes(wstr);
}

// Windows taskkill documentation https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/taskkill


// Based on https://stackoverflow.com/questions/70178895/need-win32-api-c-code-that-is-equivalent-to-taskkill-t-f-pid-xxx
// Function to terminate a process by ID
bool TerminateSingleProcessById(DWORD processId, bool forceful) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to open process with ID " << processId << L". Error: " << GetLastError() << std::endl;
        return false;
    }

    bool result = TerminateProcess(hProcess, 0) == TRUE;
    if (!result) {
        std::wcerr << L"Failed to terminate process with ID " << processId << L". Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return result;
}


// Function to terminate a process by ID
bool TerminateProcessById(DWORD parentProcessId, bool forceful, bool tree) {
    if (tree) {
        // Recursive termination of child processes
        HANDLE childSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W childPe32;
        childPe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(childSnapshot, &childPe32)) {
            do {
                // Kill children based on parent process id
                if (childPe32.th32ParentProcessID == parentProcessId) {
                    TerminateSingleProcessById(childPe32.th32ProcessID, forceful);
                }
            } while (Process32NextW(childSnapshot, &childPe32));
        }
        CloseHandle(childSnapshot);
    }

    return TerminateSingleProcessById(parentProcessId, forceful);
}

// Based on https://stackoverflow.com/questions/7956519/how-to-kill-processes-by-name-win32-api
// Function to find and terminate processes by image name
bool TerminateProcessesByImageName(const std::string& imageName, bool forceful, bool tree) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create process snapshot. Error: " << GetLastError() << std::endl;
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool processFound = false;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (wStringToString(pe32.szExeFile) == imageName) {
                if (TerminateProcessById(pe32.th32ProcessID, forceful, tree)) {
                    processFound = true;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processFound;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Not enough arguments";
        return 1;
    }

    DWORD processId = 0;
    std::string imageName;
    bool forceful = false;
    bool tree = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "/f" || arg == "/F") {
            forceful = true;
        }
        else if (arg == "/t" || arg == "/T" ) {
            tree = true;
        }
        else if ((arg == "/pid" || arg == "/PID") && i + 1 < argc) {
            processId = std::stoul(argv[++i]);
        }
        else if ((arg == "/im" || arg == "/IM") && i + 1 < argc) {
            imageName = argv[++i];
        }
    }

    bool success = false;
    if (processId != 0) {
        success = TerminateProcessById(processId, forceful, tree);
    }
    else if (!imageName.empty()) {
        success = TerminateProcessesByImageName(imageName, forceful, tree);
    }
    else {
        return 1;
    }

    return success ? 0 : 1;
}
