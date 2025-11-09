//based on : https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "patcher/ExitPatcher.hpp"

int main() {
    if (ExitPatcher::PatchExit()) {
        MessageBoxA(NULL, "exit functions patched successfully!", "success", MB_OK);        
    } else {
        MessageBoxA(NULL, "failed to patch exit functions!", "error", MB_OK);
    }
    MessageBoxA(NULL, "resetting rn!", "success", MB_OK);
    ExitPatcher::ResetExitFunctions();
    return 0;
}
