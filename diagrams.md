# PE Resolver Documentation - Diagrams

## 1. PEB Walking Structure (GetModule Function)

```mermaid
graph TD
    A[TEB] --> B[PEB]
    B --> C[PEB_LDR_DATA]
    C --> D[InMemoryOrderModuleList]
    D --> E[Node 1: kernel32.dll]
    D --> F[Node 2: ntdll.dll]
    D --> G[Node N: user32.dll]
    E --> H[DllBase: 0x7FF800000000]
    F --> I[DllBase: 0x7FF900000000]
    G --> J[DllBase: 0x7FF700000000]
    
    style A fill:#1e293b
    style B fill:#374151
    style C fill:#475569
    style E fill:#22c55e
    style F fill:#22c55e
    style G fill:#22c55e
```

## 2. PE File Structure Layout

```mermaid
graph TD
    A[Module Base] --> B[DOS Header]
    B --> C[NT Headers]
    C --> D[Optional Header]
    D --> E[Data Directories]
    E --> F[Export Directory]
    F --> G[Export Table]
    G --> H[Function Addresses]
    G --> I[Function Names]
    G --> J[Ordinals]
    
    style A fill:#1e293b
    style B fill:#22c55e
    style C fill:#475569
    style F fill:#3b82f6
    style H fill:#8b5cf6
    style I fill:#8b5cf6
    style J fill:#8b5cf6
```

## 3. GetProc Function Flow

```mermaid
flowchart TD
    A[GetProc] --> B{Valid Module?}
    B -->|No| C[Return null]
    B -->|Yes| D[Check PE Header]
    D --> E{Valid PE?}
    E -->|No| C
    E -->|Yes| F[Get Export Dir]
    F --> G{Export Exists?}
    G -->|No| C
    G -->|Yes| H{Is Ordinal?}
    H -->|Yes| I[Resolve by Ordinal]
    H -->|No| J[Search Name Table]
    I --> K[Get Function RVA]
    J --> L{Name Found?}
    L -->|No| C
    L -->|Yes| K
    K --> M{Forwarded?}
    M -->|Yes| N[Recursive Call]
    M -->|No| O[Return Address]
    N --> O
    
    style A fill:#22c55e
    style C fill:#ef4444
    style O fill:#3b82f6
```

## 4. Export Address Table Structure

```mermaid
graph LR
    A[Export Directory] --> B[Functions Array]
    A --> C[Names Array]  
    A --> D[Ordinals Array]
    
    B --> B1[CreateFileW RVA]
    B --> B2[ReadFile RVA]
    
    C --> C1["CreateFileW"]
    C --> C2["ReadFile"]
    
    D --> D1[Ordinal 0]
    D --> D2[Ordinal 1]
    
    C1 -.-> D1
    C2 -.-> D2
    D1 -.-> B1
    D2 -.-> B2
    
    style A fill:#22c55e
    style B fill:#3b82f6
    style C fill:#475569
    style D fill:#8b5cf6
```

## 5. Function Resolution Sequence

```mermaid
sequenceDiagram
    participant App
    participant GetModule as GM
    participant GetProc as GP
    participant Parser as EAT
    
    App->>GM: GetModule("kernel32")
    GM->>App: Return HMODULE
    
    App->>GP: GetProc(hModule, "Sleep")
    GP->>EAT: Parse Export Directory
    EAT->>GP: Return function tables
    GP->>EAT: Search for "Sleep"
    EAT->>GP: Found at index 245
    GP->>App: Return function address
```

## 6. Memory Layout Visualization

```mermaid
graph TB
    subgraph Process["Process Memory"]
        subgraph Modules["Loaded Modules"]
            A[ntdll.dll<br/>0x7FF900000000]
            B[kernel32.dll<br/>0x7FF800000000]
            C[user32.dll<br/>0x7FF600000000]
        end
        
        subgraph PE["PE Structure"]
            D[DOS Header]
            E[NT Headers]
            F[Export Directory]
        end
    end
    
    B --> D
    
    style A fill:#22c55e
    style B fill:#3b82f6
    style C fill:#475569
    style F fill:#ef4444
```

## 7. Function Call Chain Example

```mermaid
flowchart LR
    A[main] --> B[GetModule<br/>kernel32]
    B --> C[GetProc<br/>Sleep]
    C --> D[GetProc<br/>LoadLibraryW]
    D --> E[LoadLibraryW<br/>user32]
    E --> F[GetProc<br/>MessageBoxW]
    F --> G[Ready to Use]
    
    style A fill:#22c55e
    style G fill:#3b82f6
```

## 8. Error Handling Flow

```mermaid
flowchart TD
    A[Function Entry] --> B{Valid Input?}
    B -->|No| C[Return Error]
    B -->|Yes| D{Valid PE?}
    D -->|No| E[PE Invalid Error]
    D -->|Yes| F{Export Dir?}
    F -->|No| G[Export Missing Error]
    F -->|Yes| H{Function Found?}
    H -->|No| I[Function Not Found]
    H -->|Yes| J[Success]
    
    style C fill:#ef4444
    style E fill:#ef4444
    style G fill:#ef4444
    style I fill:#ef4444
    style J fill:#22c55e
```

## 9. Data Structure Relationships

```mermaid
classDiagram
    TEB --> PEB : ProcessEnvironmentBlock
    PEB --> PEB_LDR_DATA : Ldr
    PEB_LDR_DATA --> LDR_DATA_TABLE_ENTRY : ModuleList
    LDR_DATA_TABLE_ENTRY --> IMAGE_DOS_HEADER : DllBase
    IMAGE_DOS_HEADER --> IMAGE_NT_HEADERS : e_lfanew
    IMAGE_NT_HEADERS --> IMAGE_EXPORT_DIRECTORY : DataDirectory
    
    class TEB {
        +ProcessEnvironmentBlock
    }
    class PEB {
        +Ldr
        +ImageBaseAddress
    }
    class LDR_DATA_TABLE_ENTRY {
        +DllBase
        +BaseDllName
    }
    class IMAGE_EXPORT_DIRECTORY {
        +AddressOfFunctions
        +AddressOfNames
        +NumberOfNames
    }
```

## 10. Security Bypass Comparison

```mermaid
graph TB
    subgraph Traditional["Traditional Method"]
        A1[Static Imports] --> A2[IAT Visible]
        A2 --> A3[Easy Detection]
    end
    
    subgraph Resolver["PE Resolver Method"]
        B1[No Static Imports] --> B2[Runtime Resolution]
        B2 --> B3[Harder Detection]
    end
    
    subgraph Analysis["Analysis Impact"]
        C1[Static Analysis] --> C2{Method?}
        C2 -->|Traditional| C3[APIs Detected]
        C2 -->|PE Resolver| C4[Clean Binary]
    end
    
    style A3 fill:#ef4444
    style B3 fill:#22c55e
    style C3 fill:#ef4444
    style C4 fill:#22c55e
```

## 11. Complete Process Flow

```mermaid
graph TB
    Start([Start Application]) --> Init[Initialize]
    Init --> GetMod[Get Module Handle]
    GetMod --> GetFunc[Get Function Address]
    GetFunc --> Call[Call Function]
    Call --> End([End])
    
    GetMod --> |PEB Walk| PEB[Walk PEB Chain]
    PEB --> |Find Module| ModFound{Module Found?}
    ModFound -->|Yes| Return1[Return Handle]
    ModFound -->|No| Error1[Return NULL]
    
    GetFunc --> |Parse PE| PE[Parse PE Headers]
    PE --> |Export Table| EAT[Parse EAT]
    EAT --> |Search| Search{Function Found?}
    Search -->|Yes| Return2[Return Address]
    Search -->|No| Error2[Return NULL]
    
    style Start fill:#22c55e
    style End fill:#22c55e
    style Error1 fill:#ef4444
    style Error2 fill:#ef4444
    style Return1 fill:#3b82f6
    style Return2 fill:#3b82f6
```



