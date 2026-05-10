#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>

// Результаты инъекции для возврата в Rust
enum class InjectionResult : uint8_t {
    Success = 0,
    ProcessNotFound = 7,
    GetFullPathNameWFailed = 8,
    OpenProcessFailed = 15,
    VirtualAllocExFailed = 16,
    WriteProcessMemoryFailed = 17,
    CreateRemoteThreadFailed = 18,
    CreateToolhelp32SnapshotFailed = 5
};

// RAII обертка для дескрипторов (HANDLE)
class Handle {
private:
    HANDLE handle;
public:
    explicit Handle(HANDLE h) : handle(h) {}
    operator HANDLE() const { return handle; }
    ~Handle() { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};

// Обертка для выделенной памяти в чужом процессе
class ProcessMemory {
private:
    HANDLE hProcess;
    LPVOID address;
public:
    explicit ProcessMemory(HANDLE hProc, LPVOID addr) : hProcess(hProc), address(addr) {}
    operator LPVOID() const { return address; }
    bool write(LPCWSTR buffer, SIZE_T size) {
        SIZE_T written = 0;
        return WriteProcessMemory(hProcess, address, buffer, size, &written) && written == size;
    }
    // ВНИМАНИЕ: Мы НЕ удаляем память в деструкторе автоматически здесь, 
    // так как LoadLibraryW в другом процессе может не успеть отработать.
    // Освободим её вручную после завершения потока.
    void free() {
        if (address) {
            VirtualFreeEx(hProcess, address, 0, MEM_RELEASE);
            address = nullptr;
        }
    }
    ~ProcessMemory() { /* Авто-удаление убрано для стабильности потока */ }
};

// Функция инъекции в конкретный PID
InjectionResult InjectIntoPID(DWORD processId, LPCWSTR path, SIZE_T pathSize) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProc) return InjectionResult::OpenProcessFailed;
    Handle hProcOwned(hProc);

    LPVOID remoteAddr = VirtualAllocEx(hProcOwned, nullptr, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteAddr) return InjectionResult::VirtualAllocExFailed;

    ProcessMemory mem(hProcOwned, remoteAddr);
    if (!mem.write(path, pathSize)) {
        mem.free();
        return InjectionResult::WriteProcessMemoryFailed;
    }

    // --- ФИКС ВОРНИНГА ЗДЕСЬ ---
    // Используем reinterpret_cast через void* чтобы убрать -Wcast-function-type
    auto loadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "LoadLibraryW"))
    );
    
    if (!loadLib) {
        mem.free();
        return InjectionResult::CreateRemoteThreadFailed;
    }

    HANDLE hThread = CreateRemoteThread(hProcOwned, nullptr, 0, loadLib, remoteAddr, 0, nullptr);
    if (!hThread) {
        mem.free();
        return InjectionResult::CreateRemoteThreadFailed;
    }

    Handle hThreadOwned(hThread);
    WaitForSingleObject(hThreadOwned, INFINITE);

    // Теперь, когда поток завершился, можно безопасно чистить память
    mem.free();

    return InjectionResult::Success;
}

// Главная функция, вызываемая из Rust
extern "C" uint8_t run_injection(const wchar_t* processName, const wchar_t* libraryPath) {
    WCHAR fullPath[MAX_PATH];
    if (GetFullPathNameW(libraryPath, MAX_PATH, fullPath, nullptr) == 0) 
        return (uint8_t)InjectionResult::GetFullPathNameWFailed;

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
                InjectIntoPID(pe.th32ProcessID, fullPath, (wcslen(fullPath) + 1) * sizeof(WCHAR));
            }
        } while (Process32NextW(hSnapOwned, &pe));
    }

    return found ? (uint8_t)InjectionResult::Success : (uint8_t)InjectionResult::ProcessNotFound;
}
