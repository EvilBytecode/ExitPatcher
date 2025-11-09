#include "ExitPatcher.hpp"
#include <windows.h>
#include <vector>
#include <cstring>

namespace ExitPatcher {
    struct ExitFunction {
        const wchar_t* module;
        const char* function;
        BYTE ORGBytes[19];
        bool patched;
    };

    static ExitFunction ExitFunctions[] = {
        { L"kernelbase.dll", "TerminateProcess", {0}, false },
        { L"kernel32.dll", "TerminateProcess", {0}, false },
        { L"kernelbase.dll", "ExitProcess", {0}, false },
        { L"kernel32.dll", "ExitProcess", {0}, false },
        { L"mscoree.dll", "CorExitProcess", {0}, false },
        { L"ntdll.dll", "NtTerminateProcess", {0}, false },
        { L"ntdll.dll", "RtlExitUserProcess", {0}, false }
    };

    static const size_t EXIT_FUNCTION_COUNT = 7;
    static size_t gshcsize = 0;

    static PVOID GetFunctionAddress(const wchar_t* moduleName, const char* functionName) {
        return (PVOID)GetProcAddress(GetModuleHandleW(moduleName), functionName);
    }

    static bool ReadMemory(PVOID address, void* buffer, size_t size) {
        __try {
            memcpy(buffer, address, size);
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    static bool WriteMemory(PVOID address, const void* data, size_t size) {
        DWORD oldProtect;
        if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }

        __try {
            memcpy(address, data, size);
            VirtualProtect(address, size, oldProtect, &oldProtect);
            return true;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            VirtualProtect(address, size, oldProtect, &oldProtect);
            return false;
        }
    }

    bool PatchExit() {
        PVOID ExitThreadAddr = GetFunctionAddress(L"kernelbase.dll", "ExitThread");
        if (!ExitThreadAddr) {
            ExitThreadAddr = GetFunctionAddress(L"kernel32.dll", "ExitThread");
        }
        if (!ExitThreadAddr) return false;

#ifdef _WIN64
        std::vector<BYTE> shc;
        shc.push_back(0x48); shc.push_back(0xC7); shc.push_back(0xC1); shc.push_back(0x00); shc.push_back(0x00); shc.push_back(0x00); shc.push_back(0x00);  // MOV RCX, 0
        shc.push_back(0x48); shc.push_back(0xB8);
        uint64_t ExitThreadAddr64 = reinterpret_cast<uint64_t>(ExitThreadAddr);
        BYTE* addrBytes = reinterpret_cast<BYTE*>(&ExitThreadAddr64);
        shc.insert(shc.end(), addrBytes, addrBytes + 8);
        shc.push_back(0xFF);  
        shc.push_back(0xE0);  
#else
        std::vector<BYTE> shc;
        shc.push_back(0xB9); shc.push_back(0x00); shc.push_back(0x00); shc.push_back(0x00); shc.push_back(0x00);  
        shc.push_back(0xB8);  
        uint32_t ExitThreadAddr32 = reinterpret_cast<uint32_t>(ExitThreadAddr);
        BYTE* addrBytes = reinterpret_cast<BYTE*>(&ExitThreadAddr32);
        shc.insert(shc.end(), addrBytes, addrBytes + 4);
        shc.push_back(0xFF);  
        shc.push_back(0xE0);  
#endif

        gshcsize = shc.size();

        for (size_t i = 0; i < EXIT_FUNCTION_COUNT; i++) {
            PVOID FCEAddr = GetFunctionAddress(ExitFunctions[i].module, ExitFunctions[i].function);
            if (!FCEAddr) continue;

            if (!ReadMemory(FCEAddr, ExitFunctions[i].ORGBytes, gshcsize)) {
                ResetExitFunctions();
                return false;
            }

            if (!WriteMemory(FCEAddr, shc.data(), gshcsize)) {
                ResetExitFunctions();
                return false;
            }

            ExitFunctions[i].patched = true;
        }

        return true;
    }

    void ResetExitFunctions() {
        if (gshcsize == 0) return;
        for (size_t i = 0; i < EXIT_FUNCTION_COUNT; i++) {
            if (!ExitFunctions[i].patched) continue;
            PVOID FCEAddr = GetFunctionAddress(ExitFunctions[i].module, ExitFunctions[i].function);
            if (FCEAddr) {
                WriteMemory(FCEAddr, ExitFunctions[i].ORGBytes, gshcsize);
            }
            ExitFunctions[i].patched = false;
        }
    }
}
