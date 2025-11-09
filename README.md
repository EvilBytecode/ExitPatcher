# ExitPatcher

Preventing process termination by patching Windows exit functions through in-memory code modification. Redirects execution from process-terminating APIs to `ExitThread` to prevent premature application shutdown.

Based on the technique described in [MDSec's article on preventing Environment.Exit in in-process .NET assemblies](https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/).

## Explanation

The implementation intercepts Windows API functions that terminate the current process by patching their function bodies with shellcode that redirects execution to `ExitThread` instead. When any patched exit function is called, the shellcode executes which calls `ExitThread(0)`, terminating only the calling thread rather than the entire process.

This technique prevents in-process code (e.g., .NET assemblies loaded into the same process) from terminating the host by patching Windows exit APIs to call ExitThread. Unlike CLR-level patches of System.Environment.Exit, this works at the Windows API level—but it only intercepts exit calls made inside the same process (it does not stop external or kernel-level termination).

The shellcode is written directly into the target function's memory space using `VirtualProtect` to modify memory protection flags and `memcpy` to overwrite function bytes. Original function bytes are preserved for restoration via `ResetExitFunctions()`.

## Target Functions

The implementation patches the following exit functions across multiple DLLs:

- `kernelbase.dll::TerminateProcess`
- `kernel32.dll::TerminateProcess`
- `kernelbase.dll::ExitProcess`
- `kernel32.dll::ExitProcess`
- `mscoree.dll::CorExitProcess`
- `ntdll.dll::NtTerminateProcess`
- `ntdll.dll::RtlExitUserProcess`

Function addresses are resolved using `GetModuleHandleW` and `GetProcAddress`. If a module is not loaded or a function is not found, that specific entry is skipped without affecting other patches.

## Shellcode Generation

Shellcode is generated dynamically based on the architecture. The implementation builds position-independent code that loads the address of `ExitThread` into a register and jumps to it.

### x64 Implementation

```asm
MOV RCX, 0                    ; 48 C7 C1 00 00 00 00
MOV RAX, ExitThreadAddr       ; 48 B8 [8-byte address]
JMP RAX                       ; FF E0
```

Total size: 17 bytes

### x86 Implementation

```asm
MOV ECX, 0                    ; B9 00 00 00 00
MOV EAX, ExitThreadAddr       ; B8 [4-byte address]
JMP EAX                       ; FF E0
```

Total size: 12 bytes

The `ExitThread` address is resolved at runtime by querying `kernelbase.dll` first, falling back to `kernel32.dll` if not found. The address is embedded directly into the shellcode as an immediate value, allowing execution without additional memory dereferences.

## Memory Protection and Patching

The patching process uses Structured Exception Handling (SEH) to handle potential access violations during memory operations:

1. **ReadMemory**: Reads original function bytes into a buffer using `memcpy` wrapped in `__try/__except` to handle read violations gracefully.

2. **WriteMemory**: 
   - Calls `VirtualProtect` to change memory protection from `PAGE_EXECUTE_READ` to `PAGE_EXECUTE_READWRITE`
   - Writes shellcode bytes using `memcpy` wrapped in SEH
   - Restores original memory protection flags via `VirtualProtect`
   - If any step fails, original protection is restored and the function returns false

3. **Restoration**: `ResetExitFunctions()` iterates through all patched functions and writes the original bytes back, effectively undoing all patches.

## Implementation Details

The patching process follows this sequence:

1. Resolve `ExitThread` address from `kernelbase.dll` or `kernel32.dll`
2. Generate architecture-specific shellcode with embedded `ExitThread` address
3. For each target function:
   - Resolve function address via `GetModuleHandleW` and `GetProcAddress`
   - Read original function bytes (up to shellcode size, maximum 19 bytes)
   - Modify memory protection to `PAGE_EXECUTE_READWRITE`
   - Write shellcode bytes
   - Restore original memory protection
   - Mark function as patched
4. If any patch fails, `ResetExitFunctions()` is called to restore previously patched functions

The implementation stores original bytes in a static array (`ExitFunction::ORGBytes[19]`) which is sufficient for both x86 and x64 shellcode variants. The actual shellcode size is stored in `gshcsize` to handle variable-length shellcode correctly.

## Key Functions

- `ExitPatcher::PatchExit()` - Patches all target exit functions with redirect shellcode. Returns `true` if all patches succeed, `false` otherwise. Automatically restores patches on failure.

- `ExitPatcher::ResetExitFunctions()` - Restores original function bytes for all previously patched functions. Safe to call multiple times.

- `GetFunctionAddress(moduleName, functionName)` - Internal helper that resolves function addresses using `GetModuleHandleW` and `GetProcAddress`. Returns `nullptr` if module or function not found.

- `ReadMemory(address, buffer, size)` - Safely reads memory using SEH to handle access violations. Returns `true` on success.

- `WriteMemory(address, data, size)` - Modifies memory protection, writes data, and restores protection. Uses SEH for error handling. Returns `true` on success.

## Disclaimer

This implementation demonstrates process termination prevention through API patching. The technique modifies executable code in memory and can be detected through code integrity monitoring, memory protection analysis, or behavioral detection. Use as part of a defensive strategy for protecting host processes from premature termination by loaded code.

## License

MIT

## Credits

- MDSec for the original research on preventing Environment.Exit in in-process .NET assemblies
- Based on techniques described in [Massaging your CLR: Preventing Environment.Exit in In-Process .NET Assemblies](https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/)

