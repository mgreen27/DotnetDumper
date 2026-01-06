# DotnetDumper
A tool to quickly dump reflected assemblies from process dumps for further analysis.

## Architecture notes
- The analysis binary must match the dump/process architecture:
  - x64: `DotnetDumper.exe`
  - x86: `DotnetDumper_x86.exe`
  - ARM64: `DotnetDumper_arm64.exe`
- ARM64/ARM64EC/.NET Framework targets can require the ARM64 build to load the correct DAC.

## Reflective assembly dumping (what we can extract)
- **PE-backed modules** (including in-memory loads that still have a valid PE image base) are dumped by reading the module image from the dump.
- **Assembly.Load(byte[]) style loads** are additionally supported via a heap fallback that carves managed PE files out of `System.Byte[]` objects (deduped and capped).
- Some “dynamic” modules shown in tools like Process Hacker can be **Reflection.Emit** / DynamicMethods without a stable PE file to dump; in those cases, a full DLL may not be reconstructable from a small minidump.


Usage:   
  DotnetDumper <dumpPath> [outputFolder] [--dump-all] [--json] [--encode [key]]   
  DotnetDumper --pid <pid> [outputFolder] [--dump-all] [--json] [--encode [key]]   

Notes:
- In `--pid` mode, the tool captures a full-memory minidump by default (better assembly recovery, larger dumps).

Examples:   
  DotnetDumper C:\dumps\w3wp.dmp   
  DotnetDumper C:\dumps\w3wp.dmp C:\analysis\w3wp   
  DotnetDumper C:\dumps\w3wp.dmp --dump-all   
  DotnetDumper --pid 4242 C:\analysis\w3wp --dump-all --json   
