#include <windows.h>
#include <tlhelp32.h>
#include <processthreadsapi.h>
#include <winbase.h>
#include <wtsapi32.h>
#include <psapi.h>
#include <winsvc.h>
#include <realtimeapiset.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>
#include <sstream>

// Based on https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes

// Taken from https://cplusplus.com/forum/general/243349/
std::string wStringToString(const std::wstring& wstr) {
    static std::wstring_convert< std::codecvt_utf8<wchar_t>, wchar_t > converter;
    return converter.to_bytes(wstr);
}

// Based on https://stackoverflow.com/questions/45625222/c-get-windows-title-using-process-name
//struct param_enum
//{
//    unsigned long ulPID;
//    HWND hWnd_out;
//};
//
//HWND find_specific_window(unsigned long process_id)
//{
//    param_enum param_data;
//    param_data.ulPID = process_id;
//    param_data.hWnd_out = 0;
//    EnumWindows(enum_windows_callback, (LPARAM)&param_data);
//    return param_data.hWnd_out;
//}
//
//
//BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam)
//{
//    param_enum& param_data = *(param_enum*)lParam;
//    unsigned long process_id = 0;
//    GetWindowThreadProcessId(handle, &process_id);
//    if (param_data.ulPID != process_id)
//    {
//        return TRUE;
//    }
//    param_data.hWnd_out = handle;
//
//    return FALSE;
//}

// Process information structure
struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    DWORD sessionId;
    std::string serviceStatus = "Unknown";
    std::string sessionName = "Console";
    std::string serviceName = "N/A";
    std::string processName;
    std::string modulePath;
    std::string userName;
    std::string domainName;
    std::string windowTitle = "N/A";
    SIZE_T memoryUsage = 0;
    ULONG64 cycleTime;
};

// Function to get process list
std::vector<ProcessInfo> GetProcessList(bool verbose = false, bool svc = false) {

    std::vector<ProcessInfo> processes;
    // Take a snapshot of all processes in the system.
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Error handling
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot." << std::endl;
        return processes;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        std::cerr << "Failed to retrieve first process." << std::endl;
        return processes;
    }

    do {
        ProcessInfo pi;
        pi.pid = pe32.th32ProcessID;
        pi.parentPid = pe32.th32ParentProcessID;
        pi.processName = wStringToString(pe32.szExeFile);
        ProcessIdToSessionId(pi.pid, &pi.sessionId);

        // Taken from https://learn.microsoft.com/en-us/windows/win32/psapi/collecting-memory-usage-information-for-a-process
        // Get process memory size
        HANDLE hProcess;
        PROCESS_MEMORY_COUNTERS pmc;

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pi.pid);
        if (hProcess != NULL) {
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
            {
                pi.memoryUsage = pmc.WorkingSetSize / 1000;
            }

            // Based on https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                ULARGE_INTEGER kernelTimeValue, userTimeValue;
                userTimeValue.LowPart = userTime.dwLowDateTime;
                userTimeValue.HighPart = userTime.dwHighDateTime;

                pi.cycleTime = userTimeValue.QuadPart / 10000000.0;
            }

            // Based on https://stackoverflow.com/questions/37002790/gettokeninformation-token-owner-and-lookupaccountsida
            // Get process owner
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                DWORD len = 0;
                GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
                if (len != 0) {
                    PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, len);
                    if (pTokenUser) {
                        GetTokenInformation(hToken, TokenUser, pTokenUser, len, &len);
                        char nameUser[256] = { 0 };
                        char domainName[256] = { 0 };
                        DWORD nameUserLen = 256;
                        DWORD domainNameLen = 256;
                        SID_NAME_USE snu;
                        if (LookupAccountSidA(NULL, pTokenUser->User.Sid, nameUser, &nameUserLen, domainName, &domainNameLen, &snu)) {
                            pi.userName = nameUser;
                            pi.domainName = domainName;
                        }
                    }
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);

        // Based on https://stackoverflow.com/questions/16654686/win32-c-how-to-get-current-application-service-name
        // Determine if process is service or not and get info
        SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);

        if (hSCM != NULL)
        {
            DWORD bufferSize = 0;
            DWORD requiredBufferSize = 0;
            DWORD totalServicesCount = 0;
            EnumServicesStatusEx(hSCM,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                nullptr,
                bufferSize,
                &requiredBufferSize,
                &totalServicesCount,
                nullptr,
                nullptr);

            std::vector<BYTE> buffer(requiredBufferSize);
            EnumServicesStatusEx(hSCM,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                buffer.data(),
                buffer.size(),
                &requiredBufferSize,
                &totalServicesCount,
                nullptr,
                nullptr);

            LPENUM_SERVICE_STATUS_PROCESS services = reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(buffer.data());
            for (unsigned int i = 0; i < totalServicesCount; ++i)
            {
                ENUM_SERVICE_STATUS_PROCESS service = services[i];
                if (service.ServiceStatusProcess.dwProcessId == pi.pid)
                {
                    // This is your service.
                    pi.sessionName = "Services";
                    pi.serviceName = wStringToString(service.lpServiceName);

                    // Based on https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
                    DWORD status = service.ServiceStatusProcess.dwCurrentState;
                    if (status == 1) {
                        pi.serviceStatus = "Stopped";
                    }
                    else if (status == 2) {
                        pi.serviceStatus = "Starting";
                    }
                    else if (status == 3) {
                        pi.serviceStatus = "Stopping";
                    }
                    else if (status == 4) {
                        pi.serviceStatus = "Running";
                    }
                    else if (status == 5) {
                        pi.serviceStatus = "About to Continue";
                    }
                    else if (status == 6) {
                        pi.serviceStatus = "Pausing";
                    }
                    else if (status == 7) {
                        pi.serviceStatus = "Paused";
                    }
                }
            }

            (void)CloseServiceHandle(hSCM);
        }

        // Based on https://stackoverflow.com/questions/45625222/c-get-windows-title-using-process-name
        if (pi.sessionName == "Console") {
            //wchar_t* caption = new wchar_t[MAX_PATH * 2];
            //HWND h = find_specific_window(pi.pid);
            //GetWindowTextW(h, caption, MAX_PATH * 2);
            //pi.windowTitle = wStringToString(caption);
        }

        processes.push_back(pi);
    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return processes;
}

// Function to print process list
void PrintProcessList(const std::vector<ProcessInfo>& processes, bool verbose = false, bool svc = false) {
    // Print header
    if (verbose) {
        std::cout << "Image Name                                              PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title" << std::endl;
        std::cout << "================================================== ======== ================ =========== ============ =============== ================================================== ============ =====================================================" << std::endl;

    }
    else if (svc) {
        std::cout << "Image Name                                              PID Services" << std::endl;
        std::cout << "================================================== ======== ============================================" << std::endl;
    }
    else {
        std::cout << "Image Name                                              PID Session Name        Session#    Mem Usage" << std::endl;
        std::cout << "================================================== ======== ================ =========== ============" << std::endl;
    }

    // Print process information
    for (const auto& process : processes) {
        if (verbose) {
            std::cout << std::left
                << std::setw(50) << process.processName
                << " " << std::right
                << std::setw(8) << process.pid
                << " " << std::left
                << std::setw(16) << process.sessionName
                << " " << std::right
                << std::setw(11) << process.sessionId
                << " "
                << std::setw(10) << process.memoryUsage
                << std::setw(2) << " K"
                << " " << std::left
                << std::setw(15) << process.serviceStatus
                << " "
                << std::setw(50) << ((process.userName.length() > 0) ? process.domainName + "\\" + process.userName : "")
                << " " << std::right
                << std::setw(12) << process.cycleTime
                << " " << std::left
                << std::setw(53) << process.windowTitle
                << std::endl;
        }
        else if (svc) {
            std::cout << std::left
                << std::setw(50) << process.processName
                << " " << std::right
                << std::setw(8) << process.pid
                << " " << std::left
                << std::setw(44) << process.serviceName
                << std::endl;
        }
        else {
            std::cout << std::left
                << std::setw(50) << process.processName
                << " " << std::right
                << std::setw(8) << process.pid
                << " " << std::left
                << std::setw(16) << process.sessionName
                << " " << std::right
                << std::setw(11) << process.sessionId
                << " "
                << std::setw(10) << process.memoryUsage
                << std::setw(2) << " K"
                << std::endl;
        }
    }
}

// Main function with command-line argument parsing
int main(int argc, char* argv[]) {
    // Switches
    bool verbose = false;
    bool svc = false;

    // Parse command-line arguments and set flags
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "/v" || arg == "/V") {
            verbose = true;
        }
        if (arg == "/svc" || arg == "/SVC") {
            svc = true;
        }
    }

    // Error check flags
    if (verbose && svc) {
        std::cerr << "/V and /SVC flags cannot be used together." << std::endl;
        return 1;
    }

    // Try catch block in case of errors
    try {
        // Get and print process list
        std::vector<ProcessInfo> processes = GetProcessList(verbose, svc);
        PrintProcessList(processes, verbose, svc);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}