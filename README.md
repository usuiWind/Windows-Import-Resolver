# Windows-PE-Walker
# PE Resolver Library

A lightweight Windows PE (Portable Executable) parser and function resolver that dynamically loads modules and resolves API functions at runtime without relying on the Import Address Table (IAT).

## Overview

This library implements manual PE parsing by walking the Process Environment Block (PEB) and Export Address Table (EAT) to resolve Windows API functions dynamically. This approach is commonly used in:

- Malware research and analysis
- Red team security tools
- Anti-analysis and evasion techniques
- Educational purposes for understanding Windows internals


## Features

- **PEB Walking**: Enumerates loaded modules directly from the Process Environment Block
- **Manual EAT Parsing**: Resolves function addresses by parsing Export Address Tables
- **Export Forwarding Support**: Handles forwarded exports (e.g., kernel32 → kernelbase)
- **Ordinal Support**: Resolves functions by both name and ordinal
- **No Static Imports**: Avoids detection by static analysis tools that scan IAT

## Architecture

### Core Components

1. **`GetModule(LPCWSTR module_name)`**
   - Walks the PEB's InMemoryOrderModuleList
   - Finds loaded modules by name
   - Returns module base address

2. **`GetProc(HMODULE moduleBase, const char* functionName)`**
   - Parses PE headers and validates structure
   - Locates and parses Export Directory
   - Resolves function addresses from EAT
   - Handles export forwarding chains

3. **Helper Functions**
   - `PeHeaderCheck()`: Validates PE structure integrity
   - `RvaToPtr()`: Converts Relative Virtual Addresses to pointers

### PE Structure Navigation

```
PE File Structure:
├── DOS Header
├── NT Headers
│   ├── File Header
│   └── Optional Header
│       └── Data Directories
│           └── Export Directory
└── Export Address Table (EAT)
    ├── Function Address Array
    ├── Function Name Array
    └── Ordinal Array
```

## Usage Example

```cpp
#include "resolver.h"

int main() {
    // Get kernel32.dll base address
    HMODULE kernel32 = GetModule(L"kernel32.dll");
    
    // Resolve Sleep function
    auto sleep_ = reinterpret_cast<VOID(WINAPI*)(DWORD)>(
        GetProc(kernel32, "Sleep")
    );
    
    // Use the resolved function
    sleep_(1000);
    
    return 0;
}
```

## Technical Details

### PEB Structure Access
```cpp
PEB* peb = ((PEB*)((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock);
```

The library accesses the Thread Environment Block (TEB) to get the Process Environment Block (PEB), which contains the loader data structure with all loaded modules.

### Export Forwarding
The resolver handles export forwarding where functions in one DLL actually point to functions in another DLL:
- Detects forwarded exports in the export directory
- Parses forwarding strings (e.g., "KERNELBASE.Sleep")
- Recursively resolves the target function

### Ordinal Resolution
Supports both named and ordinal-based function resolution:
- Named: `GetProc(module, "FunctionName")`
- Ordinal: `GetProc(module, (char*)ordinal_number)`

## Build Requirements

- **Compiler**: MSVC or MinGW with C++11 support
- **Platform**: Windows x64 (easily adaptable to x86)
- **Dependencies**: 
  - Windows SDK headers
  - Custom `pe_structs.h` (PE structure definitions)
  - `errors.hpp` (error code definitions)

## Security Considerations

⚠️ **Warning**: This code is designed for educational and authorized security testing purposes only.

### Defensive Applications
- Understanding malware techniques
- Developing detection mechanisms
- Security research and analysis

### Potential Misuse
- Malware development
- Unauthorized system access
- Evasion of security controls

## Known Limitations

1. **x64 Only**: Currently hardcoded for 64-bit PE files
2. **Windows Only**: Relies on Windows-specific structures (PEB/TEB)
3. **CRT Dependencies**: Still requires some C runtime functions
4. **Error Handling**: Limited error reporting and recovery

## Code Quality Issues

The current implementation has some bugs that need fixing:
- Proper type definitions for GetProc
- Missing function closing brace
- Potential memory access violations without proper bounds checking

## Future Improvements

- [ ] Add x86/x64 compatibility layer
- [ ] Implement syscall resolution
- [ ] Add comprehensive error handling
- [ ] Support for delay-loaded imports
- [ ] Anti-debugging and anti-analysis features

## Educational Value

This project demonstrates:
- Windows PE file format internals
- Process and thread environment blocks
- Dynamic library loading mechanisms
- Export table structure and parsing
- Low-level Windows API interaction

## Legal Notice

This software is provided for educational and authorized security research purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

## References

- [Microsoft PE/COFF Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Windows Internals Documentation](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Malware Analysis Techniques](https://www.sans.org/white-papers/malware-analysis/)

---

**Disclaimer**: This project is for educational purposes and authorized security research only. Always ensure you have proper authorization before using these techniques in any environment.
