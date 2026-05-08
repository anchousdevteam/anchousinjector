#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <cstdint>

enum class InjectionResult : uint8_t {
    Success = 0,
    CommandLineToArgvWFailed,
    GetStdHandleFailed,
    WriteConsoleWFailed,
    IncorrectArguments,
    CreateToolhelp32SnapshotFailed,
    Process32FirstWFailed,
    ProcessNotFound,
    GetFullPathNameWFailed,
    Module32FirstWFailed,
    CopyFileWFailed,
    CreateWellKnownSidFailed,
    GetNamedSecurityInfoWFailed,
    SetEntriesInAclWFailed,
    SetNamedSecurityInfoWFailed,
    OpenProcessFailed,
    VirtualAllocExFailed,
    WriteProcessMemoryFailed,
    CreateRemoteThreadFailed,
    WaitForSingleObjectFailed,
};

class Handle {
private:
    HANDLE handle;
public:
    explicit Handle(HANDLE handle) : handle(handle) {}
    operator HANDLE() const { return handle; }
    ~Handle() { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};

template<class T>
class LocalMemoryHandle {
private:
    T val;
public:
    explicit LocalMemoryHandle(T val) : val(val) {}
    operator T() const { return val; }
    ~LocalMemoryHandle() { if (val) LocalFree(val); }
};

class ProcessMemory {
private:
    HANDLE hProcess;
    LPVOID address;
public:
    explicit ProcessMemory(HANDLE hProcess, LPVOID address) : hProcess(hProcess), address(address) {}
    operator LPVOID() const { return address; }
    bool write(LPCWSTR buffer, SIZE_T size) {
        SIZE_T written = 0;
        return WriteProcessMemory(hProcess, address, buffer, size, &written) && written == size;
    }
    ~ProcessMemory() { VirtualFreeEx(hProcess, address, 0, MEM_RELEASE); }
};

InjectionResult InjectIntoPID(DWORD processId, LPCWSTR path2, SIZE_T pathSize) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProc) return InjectionResult::OpenProcessFailed;
    Handle hProcOwned(hProc);

    LPVOID remoteAddr = VirtualAllocEx(hProcOwned, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) return InjectionResult::VirtualAllocExFailed;

    ProcessMemory mem(hProcOwned, remoteAddr);
    if (!mem.write(path2, pathSize)) return InjectionResult::WriteProcessMemoryFailed;

    auto loadLib = GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcOwned, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLib, remoteAddr, 0, nullptr);
    if (!hThread) return InjectionResult::CreateRemoteThreadFailed;

    Handle hThreadOwned(hThread);
    WaitForSingleObject(hThreadOwned, INFINITE);

    return InjectionResult::Success;
}

extern "C" uint8_t run_injection(const wchar_t* processName, const wchar_t* libraryPath) {
    const WCHAR filePrefix[] = L"injected_";
    WCHAR buffer1[MAX_PATH];
    LPWSTR ptrFilePart = nullptr;
    
    if (GetFullPathNameW(libraryPath, MAX_PATH, buffer1, &ptrFilePart) == 0) 
        return (uint8_t)InjectionResult::GetFullPathNameWFailed;

    WCHAR path2[MAX_PATH];
    size_t dirLen = ptrFilePart - buffer1;
    for (size_t i = 0; i < dirLen; ++i) path2[i] = buffer1[i];
    
    LPWSTR curr = path2 + dirLen;
    for (const WCHAR* p = filePrefix; *p; ++p) *curr++ = *p;
    for (const WCHAR* p = ptrFilePart; *p; ++p) *curr++ = *p;
    *curr = L'\0';

    if (!CopyFileW(buffer1, path2, FALSE)) return (uint8_t)InjectionResult::CopyFileWFailed;

    bool found = false;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return (uint8_t)InjectionResult::CreateToolhelp32SnapshotFailed;
    Handle hSnapOwned(hSnap);

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapOwned, &pe)) {
        do {
            if (!lstrcmpW(pe.szExeFile, processName)) {
                found = true;
                InjectIntoPID(pe.th32ProcessID, path2, (wcslen(path2) + 1) * sizeof(WCHAR));
            }
        } while (Process32NextW(hSnapOwned, &pe));
    }

    return found ? (uint8_t)InjectionResult::Success : (uint8_t)InjectionResult::ProcessNotFound;
}