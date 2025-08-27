# PE Resolver Documentation - Diagrams

## 1. PEB Walking Structure (GetModule Function)

```mermaid
graph TD
    A[Thread Environment Block - TEB] --> B[Process Environment Block - PEB]
    B --> C[PEB_LDR_DATA Structure]
    C --> D[InMemoryOrderModuleList]
    D --> E[LIST_ENTRY Node 1]
    D --> F[LIST_ENTRY Node 2]
    D --> G[LIST_ENTRY Node N]
    E --> H[LDR_DATA_TABLE_ENTRY]
    F --> I[LDR_DATA_TABLE_ENTRY]
    G --> J[LDR_DATA_TABLE_ENTRY]
    H --> K[BaseDllName: kernel32.dll<br/>DllBase: 0x7FF800000000]
    I --> L[BaseDllName: ntdll.dll<br/>DllBase: 0x7FF900000000]
    J --> M[BaseDllName: user32.dll<br/>DllBase: 0x7FF700000000]
    
    style A fill:#e1f5fe
    style B fill:#f3e5f5
    style C fill:#fff3e0
    style K fill:#e8f5e8
    style L fill:#e8f5e8
    style M fill:#e8f5e8
```

The `GetModule` function traverses the Process Environment Block (PEB) to locate loaded modules in memory without using traditional Windows APIs.

## 2. PE File Structure Layout

```mermaid
graph TD
    A[Module Base Address] --> B[DOS Header]
    B --> C[DOS Stub]
    C --> D[NT Headers]
    D --> E[File Header]
    D --> F[Optional Header]
    F --> G[Data Directories Array]
    G --> H[Export Directory Entry]
    G --> I[Import Directory Entry]
    G --> J[Resource Directory Entry]
    G --> K[Other Directories...]
    H --> L[Export Directory Table]
    L --> M[Function Address Array]
    L --> N[Function Name Array]
    L --> O[Ordinal Array]
    
    style A fill:#ffebee
    style B fill:#e8f5e8
    style D fill:#fff3e0
    style L fill:#e1f5fe
    style M fill:#f3e5f5
    style N fill:#f3e5f5
    style O fill:#f3e5f5
```

This shows the internal structure of a Windows PE (Portable Executable) file and how the resolver navigates to the Export Address Table (EAT).

## 3. GetProc Function Flow

```mermaid
flowchart TD
    A[GetProc Called] --> B{Valid Module?}
    B -->|No| C[Return nullptr]
    B -->|Yes| D[PeHeaderCheck]
    D --> E{Valid PE?}
    E -->|No| C
    E -->|Yes| F[Get Export Directory]
    F --> G{Export Dir Exists?}
    G -->|No| C
    G -->|Yes| H[Get EAT Tables]
    H --> I{Function Name is Ordinal?}
    I -->|Yes| J[Resolve by Ordinal]
    I -->|No| K[Search Name Table]
    J --> L[Get Function RVA]
    K --> M{Name Found?}
    M -->|No| C
    M -->|Yes| N[Get Ordinal Index]
    N --> L
    L --> O{Is Forwarded Export?}
    O -->|Yes| P[Parse Forward String]
    O -->|No| Q[Convert RVA to Address]
    P --> R[Load Target Module]
    R --> S[Recursive GetProc Call]
    S --> T[Return Function Address]
    Q --> T
    
    style A fill:#e8f5e8
    style C fill:#ffebee
    style T fill:#e1f5fe
    style P fill:#fff3e0
    style S fill:#f3e5f5
```

Complete flow of the `GetProc` function showing validation, searching, and export forwarding handling.

## 4. Export Address Table Structure

```mermaid
graph LR
    A[Export Directory] --> B[AddressOfFunctions]
    A --> C[AddressOfNames]  
    A --> D[AddressOfNameOrdinals]
    
    B --> E[Function RVAs Array]
    E --> E1[RVA 0: CreateFileW]
    E --> E2[RVA 1: ReadFile]
    E --> E3[RVA 2: WriteFile]
    E --> E4[RVA N: ...]
    
    C --> F[Name RVAs Array]
    F --> F1[RVA: "CreateFileW"]
    F --> F2[RVA: "ReadFile"] 
    F --> F3[RVA: "WriteFile"]
    F --> F4[RVA: ...]
    
    D --> G[Ordinal Index Array]
    G --> G1[Index: 0]
    G --> G2[Index: 1]
    G --> G3[Index: 2]
    G --> G4[Index: ...]
    
    F1 -.-> G1
    F2 -.-> G2
    F3 -.-> G3
    G1 -.-> E1
    G2 -.-> E2
    G3 -.-> E3
    
    style A fill:#e8f5e8
    style E fill:#e1f5fe
    style F fill:#fff3e0
    style G fill:#f3e5f5
```

Shows how the three arrays in the Export Address Table work together to resolve function names to addresses.

## 5. Function Resolution Sequence

```mermaid
sequenceDiagram
    participant App as Application
    participant GM as GetModule
    participant PEB as PEB Walker
    participant GP as GetProc
    participant EAT as Export Parser
    participant Fwd as Forwarder Handler
    
    App->>GM: GetModule(L"kernel32.dll")
    GM->>PEB: Walk InMemoryOrderModuleList
    PEB->>GM: Return module base address
    GM->>App: Return HMODULE
    
    App->>GP: GetProc(hModule, "Sleep")
    GP->>EAT: Parse Export Directory
    EAT->>GP: Return function tables
    GP->>EAT: Search name table for "Sleep"
    EAT->>GP: Found at ordinal index 245
    GP->>EAT: Get RVA from function array[245]
    EAT->>GP: Return RVA 0x12340
    
    alt Is Forwarded Export
        GP->>Fwd: Parse "KERNELBASE.Sleep"
        Fwd->>GM: GetModule(L"kernelbase.dll")
        Fwd->>GP: Recursive GetProc(kernelbase, "Sleep")
        GP->>App: Return final function address
    else Direct Export
        GP->>GP: Convert RVA to absolute address
        GP->>App: Return function address
    end
```

Timeline showing the interaction between different components during function resolution.

## 6. Memory Layout Visualization

```mermaid
graph TB
    subgraph "Process Memory Space"
        A[0x00000000] --> B[User Mode Space]
        B --> C[Stack]
        B --> D[Heap]
        B --> E[Loaded Modules]
        
        subgraph "Loaded Modules"
            E1[ntdll.dll<br/>0x7FF900000000]
            E2[kernel32.dll<br/>0x7FF800000000]
            E3[kernelbase.dll<br/>0x7FF700000000]
            E4[user32.dll<br/>0x7FF600000000]
        end
        
        subgraph "PE Structure (kernel32.dll)"
            F[DOS Header<br/>+0x0000]
            G[NT Headers<br/>+0x00F8]
            H[Section Headers<br/>+0x0108]
            I[.text Section<br/>+0x1000]
            J[.data Section<br/>+0x5000]
            K[.rdata Section<br/>+0x6000]
            L[Export Directory<br/>+0x6100]
        end
        
        E2 --> F
    end
    
    style E1 fill:#e8f5e8
    style E2 fill:#e1f5fe
    style E3 fill:#fff3e0
    style E4 fill:#f3e5f5
    style L fill:#ffebee
```

Visual representation of how modules are loaded in process memory and their internal PE structure.

## 7. Function Call Chain Example

```mermaid
graph LR
    A[main()] --> B[GetModule<br/>L"kernel32.dll"]
    B --> C[GetProc<br/>kernel32, "Sleep"]
    C --> D[GetProc<br/>kernel32, "LoadLibraryW"]
    D --> E[LoadLibraryW_<br/>L"user32.dll"]
    E --> F[GetProc<br/>user32, "MessageBoxW"]
    F --> G[Function Pointers<br/>Ready for Use]
    
    style A fill:#e8f5e8
    style G fill:#e1f5fe
```

Example execution flow from your main() function showing the sequence of API resolution.

## 8. Error Handling Flow

```mermaid
flowchart TD
    A[Function Entry] --> B{Input Validation}
    B -->|Invalid| C[Return nullptr/Error Code]
    B -->|Valid| D[Core Processing]
    D --> E{PE Header Valid?}
    E -->|No| F[Return get_pe_header_invalid]
    E -->|Yes| G{Export Directory Found?}
    G -->|No| H[Return get_export_dir_missing]
    G -->|Yes| I{Function Found?}
    I -->|No| J[Return get_function_not_found]
    I -->|Yes| K[Success - Return Function Address]
    
    style C fill:#ffebee
    style F fill:#ffebee
    style H fill:#ffebee
    style J fill:#ffebee
    style K fill:#e8f5e8
```

Error handling paths and return codes for robust function resolution.

## 9. Data Structure Relationships

```mermaid
classDiagram
    class TEB {
        +ProcessEnvironmentBlock: PEB*
        +NtCurrentTeb(): TEB*
    }
    
    class PEB {
        +Ldr: PEB_LDR_DATA*
        +ImageBaseAddress: PVOID
    }
    
    class PEB_LDR_DATA {
        +InMemoryOrderModuleList: LIST_ENTRY
    }
    
    class LDR_DATA_TABLE_ENTRY {
        +InMemoryOrderLinks: LIST_ENTRY
        +DllBase: PVOID
        +BaseDllName: UNICODE_STRING
    }
    
    class IMAGE_DOS_HEADER {
        +e_magic: WORD
        +e_lfanew: LONG
    }
    
    class IMAGE_NT_HEADERS64 {
        +Signature: DWORD
        +OptionalHeader: IMAGE_OPTIONAL_HEADER64
    }
    
    class IMAGE_EXPORT_DIRECTORY {
        +AddressOfFunctions: DWORD
        +AddressOfNames: DWORD
        +AddressOfNameOrdinals: DWORD
        +NumberOfNames: DWORD
        +Base: DWORD
    }
    
    TEB --> PEB
    PEB --> PEB_LDR_DATA
    PEB_LDR_DATA --> LDR_DATA_TABLE_ENTRY
    LDR_DATA_TABLE_ENTRY --> IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER --> IMAGE_NT_HEADERS64
    IMAGE_NT_HEADERS64 --> IMAGE_EXPORT_DIRECTORY
```

UML-style class diagram showing relationships between Windows data structures.

## 10. Security Bypass Visualization

```mermaid
graph TB
    subgraph "Traditional API Loading"
        A1[Static Imports] --> A2[Import Address Table]
        A2 --> A3[Loader Resolves at Load Time]
        A3 --> A4[Easy Static Analysis Detection]
    end
    
    subgraph "PE Resolver Approach"
        B1[No Static Imports] --> B2[Runtime Resolution]
        B2 --> B3[PEB Walking + EAT Parsing]
        B3 --> B4[Dynamic Function Loading]
        B4 --> B5[Harder to Detect/Analyze]
    end
    
    subgraph "Analysis Tools Impact"
        C1[Static Analysis Tools] --> C2{Check IAT?}
        C2 -->|Traditional| C3[Detects API Usage]
        C2 -->|PE Resolver| C4[No Static Imports Found]
        
        D1[Dynamic Analysis Tools] --> D2{Monitor API Calls?}
        D2 -->|Both Methods| D3[Can Still Detect Runtime Usage]
    end
    
    style A4 fill:#ffebee
    style B5 fill:#e8f5e8
    style C3 fill:#ffebee
    style C4 fill:#e8f5e8
```

Comparison showing how the PE resolver approach evades static analysis detection.

## Usage Instructions

1. **Save this file** as `DIAGRAMS.md` in your GitHub repository
2. **GitHub will automatically render** all the Mermaid diagrams
3. **Link to sections** in your main README using:
   ```markdown
   See [Function Flow Diagram](DIAGRAMS.md#3-getproc-function-flow) for details.
   ```

## Adding to Your README

You can embed individual diagrams in your main README by copying the specific Mermaid code blocks you need.

### Example Integration:
```markdown
## Architecture Overview

The PE resolver works by walking the PEB structure:

```mermaid
graph TD
    A[GetModule] --> B[PEB Walker]
    B --> C[Find Module]
    C --> D[GetProc]
    D --> E[Parse Export Table]
```

For more detailed diagrams, see [DIAGRAMS.md](DIAGRAMS.md).
```
```
