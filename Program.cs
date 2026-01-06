using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Runtime;

namespace DotnetDumper
{
    internal class Program
    {
        // Suspicious patterns, treated as REGEX
        private static readonly string[] SuspiciousPatternStrings =
        {
            @"sekurlsa::logonpasswords",
            @"ERROR kuhl",
            @" -w hidden ",
            @"Koadic\.",
            @"ReflectiveLoader",
            @"%s as %s\\%s: %d",
            @"\[System\.Convert\]::FromBase64String\(",
            @"/meterpreter/",
            @"/ -[eE][decoman]{0,41} ['""]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/",
            @"  (sEt|SEt|SeT|sET|seT)  ",
            @"\);iex ",
            @"Nir Sofer",
            @"impacket\.",
            @"\[[\+\-!E]\] (exploit|target|vulnerab|shell|inject)/",
            @"0000FEEDACDC}",
            @"vssadmin delete shadows",
            @"\.exe delete shadows",
            @" shadowcopy delete",
            @" delete catalog -quiet",
            @"stratum\+tcp://",
            @"\\\\(Debug|Release)\\\\(Key[lL]og|[Ii]nject|Steal|By[Pp]ass|Amsi|Dropper|Loader|CVE\-)/",
            @"(Dropper|Bypass|Injection|Potato)\.pdb",
            @"Mozilla/5\.0",
            @"amsi\.dllATVSH",
            @"BeaconJitter",
            @"main\.Merlin",
            @"\x48\x83\xec\x50\x4d\x63\x68\x3c\x48\x89\x4d\x10",
            @"}{0}""-f ",
            @"HISTORY=/dev/null",
            @" /tmp/x;",
            @"comsvcs(\.dll)?[, ]{1,2}(MiniDump|#24)/",
            @"AmsiScanBuffer",
            // Literal "**" fixed as regex \*\*
            @"%%%%%%%%%%%######%%%#%%####%  &%%\*\*#",
            @"://",
            @"TVqQAAMAAAAEAAAA",
            @"FromBase64String",
            @"Assembly\.Load\(\)",
            @"cmd\.exe",
            @"powershell",
            @"\bpwsh\b",
            @"msiexec",
            @"wscript",
            @"cscript",
            @"/c ",
            @"-enc",
            @"-encodedcommand",
            @"invoke-webrequest",
            @"webclient",
            @"downloadfile",
            @"net user",
            @"add user",
            @"add localgroup",
            @"mimikatz",
            @"procdump",
            @"rundll32"
        };

        // Compiled regexes (case-insensitive)
        private static readonly Regex[] SuspiciousRegexes =
            SuspiciousPatternStrings
                .Select(p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase))
                .ToArray();

        // Generic benign domains to exclude from suspicious strings
        private static readonly string[] BenignDomains =
        {
            // Generic Microsoft ecosystem
            ".microsoft.com",
            ".msftncsi.com",

            // SOAP / XML / WSDL / Serialization
            "xmlsoap.org",
            "schemas.microsoft.com",
            "schemas.datacontract.org",
            "www.w3.org",

            // UI / Web resource noise
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "ajax.googleapis.com",
            "www.mozilla.org",
            "www.w3schools.com",

            // Certificate revocation / OCSP
            "ocsp.",
            "crl.",
            "digicert.com",
            "verisign.com"
        };

        private static readonly Encoding Utf8NoBomSafe =
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);

        // baseName -> list of SHA256 hashes for unique binaries we've dumped
        private static readonly Dictionary<string, List<string>> AssemblyHashes =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        // Regex for IPv4 extraction
        private static readonly Regex Ipv4Regex = new Regex(
            @"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b",
            RegexOptions.Compiled);

        private static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintUsage();
                return 1;
            }

            bool dumpAllNonMicrosoft = false;
            bool outputJson = false;
            string? encodeKey = null;
            string dumpPath = string.Empty;
            string? outputFolder = null;
            int? targetPid = null;

            // Args:
            //  DotnetDumper <dumpPath> [outputFolder] [--dump-all] [--json] [--encode [key]]
            //  DotnetDumper --pid <pid> [outputFolder] [--dump-all] [--json] [--encode [key]]

            bool pidMode = IsPidFlag(args[0]);
            int startIndex;
            if (pidMode)
            {
                if (args.Length < 2)
                {
                    PrintUsage();
                    return 1;
                }

                if (!int.TryParse(args[1], out int parsedPid) || parsedPid <= 0)
                {
                    Console.Error.WriteLine($"[!] Invalid PID: {args[1]}");
                    return 1;
                }

                targetPid = parsedPid;
                startIndex = 2;
            }
            else
            {
                dumpPath = args[0];
                startIndex = 1;
            }

            for (int i = startIndex; i < args.Length; i++)
            {
                if (IsDumpAllFlag(args[i]))
                    dumpAllNonMicrosoft = true;
                else if (IsJsonFlag(args[i]))
                    outputJson = true;
                else if (IsEncodeFlag(args[i]))
                {
                    // Default to "infected" if no key provided or next arg is another flag
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                        encodeKey = args[++i];
                    else
                        encodeKey = "infected";
                }
                else if (outputFolder == null)
                    outputFolder = args[i];
            }

            if (targetPid != null)
            {
                string pidLabel = $"pid{targetPid.Value}";
                try
                {
                    using Process p = Process.GetProcessById(targetPid.Value);
                    pidLabel = SanitizeFileName($"{p.ProcessName}_{targetPid.Value}");
                }
                catch
                {
                    // best effort only
                }

                // This tool is for .NET triage only. If the target is not a CLR/.NET process, exit early.
                if (!OperatingSystem.IsWindows())
                {
                    Console.Error.WriteLine("[!] --pid mode is only supported on Windows.");
                    return 2;
                }

                bool isClr = IsLikelyClrProcess(targetPid.Value, out string? clrDetectError);
                if (!isClr && clrDetectError == null)
                {
                    Console.WriteLine($"[i] PID {targetPid.Value} does not appear to be a CLR/.NET process. Exiting.");
                    return 0;
                }

                // Preflight (preferred): ask Windows what machine the *process* is.
                // This avoids module enumeration overhead and works even when module listing is restricted.
                if (TryGetProcessMachineInfo(targetPid.Value, out var processMachineArch, out var nativeMachineArch, out var machineErr))
                {
                    if (processMachineArch != null && processMachineArch.Value != RuntimeInformation.ProcessArchitecture)
                    {
                        Console.Error.WriteLine($"[!] Process machine is {processMachineArch.Value} but you are running {RuntimeInformation.ProcessArchitecture}.");
                        Console.Error.WriteLine($"[!] Run: {GetRecommendedDumperBinaryName(processMachineArch.Value)}");
                        return 2;
                    }
                }
                else if (machineErr != null)
                {
                    Console.WriteLine($"[i] Preflight process-machine check unavailable: {machineErr}");
                }

                // Preflight: if we can infer the CLR architecture from module paths, avoid taking a dump
                // that this build cannot analyze (common for Desktop CLR on ARM64/ARM64EC).
                if (TryGetClrModuleArchHintFromLiveProcess(targetPid.Value, out var liveClrArchHint, out var liveClrModulePath, out var liveClrHintError))
                {
                    if (liveClrArchHint == System.Runtime.InteropServices.Architecture.Arm64 &&
                        RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64)
                    {
                        Console.Error.WriteLine($"[!] Run: {GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture.Arm64)}");
                        return 2;
                    }

                    if (liveClrArchHint == System.Runtime.InteropServices.Architecture.X64 &&
                        RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.Arm64)
                    {
                        Console.Error.WriteLine($"[!] Run: {GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture.X64)}");
                        return 2;
                    }
                }
                else if (liveClrHintError != null)
                {
                    // Best-effort only; don't block dumping if we can't inspect modules.
                    Console.WriteLine($"[i] Preflight CLR-arch hint unavailable: {liveClrHintError}");
                }

                if (string.IsNullOrWhiteSpace(outputFolder))
                    outputFolder = Path.Combine(Environment.CurrentDirectory, $"{pidLabel}_analysis");

                Directory.CreateDirectory(outputFolder);

                dumpPath = Path.Combine(outputFolder, $"{pidLabel}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.dmp");

                // If we couldn't enumerate modules (often access denied), fall back to a short dump+check.
                // If it's not CLR, we delete the dump and exit.
                if (!isClr && clrDetectError != null)
                {
                    Console.WriteLine($"[i] Unable to determine CLR status for PID {targetPid.Value} ({clrDetectError}).");
                    Console.WriteLine("[i] Capturing a small process-style dump to determine if CLR is present...");
                }
                else
                {
                    Console.WriteLine($"[+] CLR/.NET process detected for PID {targetPid.Value}. Capturing process dump...");
                }

                Console.WriteLine($"[+] Dump path: {dumpPath}");

                if (!TryWriteProcessDump(targetPid.Value, dumpPath, out string? dumpError))
                {
                    Console.Error.WriteLine($"[!] Failed to write process dump: {dumpError}");
                    return 2;
                }

                if (!isClr && clrDetectError != null)
                {
                    if (!DumpContainsClr(dumpPath, out string? dumpClrError))
                    {
                        TryDeleteFile(dumpPath);
                        Console.WriteLine($"[i] Dump does not contain a CLR/.NET runtime. Exiting."
                            + (dumpClrError != null ? $" ({dumpClrError})" : ""));
                        return 0;
                    }

                    Console.WriteLine("[+] CLR/.NET runtime detected in dump. Continuing triage.");
                }
            }

            if (!File.Exists(dumpPath))
            {
                Console.Error.WriteLine($"[!] Dump not found: {dumpPath}");
                return 1;
            }

            if (string.IsNullOrWhiteSpace(outputFolder))
            {
                string dir = Path.GetDirectoryName(dumpPath) ?? Environment.CurrentDirectory;
                string baseName = Path.GetFileNameWithoutExtension(dumpPath);
                outputFolder = Path.Combine(dir, $"{baseName}_analysis");
            }

            Directory.CreateDirectory(outputFolder);

            try
            {
                RunTriage(dumpPath, outputFolder, dumpAllNonMicrosoft, outputJson, encodeKey);
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] Triage failed:");
                Console.Error.WriteLine(ex);
                return 2;
            }
        }

        private static bool IsDumpAllFlag(string s) =>
            s.Equals("--dump-all", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("-dump-all", StringComparison.OrdinalIgnoreCase);

        private static bool IsJsonFlag(string s) =>
            s.Equals("--json", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("-json", StringComparison.OrdinalIgnoreCase);

        private static bool IsEncodeFlag(string s) =>
            s.Equals("--encode", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("-encode", StringComparison.OrdinalIgnoreCase);

        private static bool IsPidFlag(string s) =>
            s.Equals("--pid", StringComparison.OrdinalIgnoreCase) ||
            s.Equals("-pid", StringComparison.OrdinalIgnoreCase);

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  DotnetDumper <dumpPath> [outputFolder] [--dump-all] [--json] [--encode [key]]");
            Console.WriteLine("  DotnetDumper --pid <pid> [outputFolder] [--dump-all] [--json] [--encode [key]]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --dump-all      Dump all non-Microsoft assemblies (not just dynamic)");
            Console.WriteLine("  --json          Output modules.json and patch_detection.json");
            Console.WriteLine("  --encode [key]  RC4 encode dumped assemblies (evades AV), saves as .bin");
            Console.WriteLine("                  Default key: 'infected'");
            Console.WriteLine("  --pid <pid>     Capture a Windows process dump first, then triage it");
            Console.WriteLine("                  NOTE: dump capture uses a 'process-style' minidump (not full-memory).");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp C:\\analysis\\w3wp");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp --dump-all --json");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp --encode");
            Console.WriteLine("  DotnetDumper --pid 4242 C:\\analysis\\w3wp --dump-all --json");
        }

        [Flags]
        private enum MINIDUMP_TYPE : uint
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithTokenInformation = 0x00004000,
        }

        [DllImport("dbghelp.dll", SetLastError = true)]
        private static extern bool MiniDumpWriteDump(
            IntPtr hProcess,
            int processId,
            Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
            MINIDUMP_TYPE dumpType,
            IntPtr exceptionParam,
            IntPtr userStreamParam,
            IntPtr callbackParam);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process2(
            IntPtr hProcess,
            out ushort processMachine,
            out ushort nativeMachine);

        private const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0x0000;
        private const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        private const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
        private const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

        private static bool TryWriteProcessDump(int pid, string dumpPath, out string? error)
        {
            if (!OperatingSystem.IsWindows())
            {
                error = "--pid mode is only supported on Windows.";
                return false;
            }

            try
            {
                using Process process = Process.GetProcessById(pid);

                // Process-style dump (not full-memory). This is a compromise between fidelity and size.
                MINIDUMP_TYPE flags =
                    MINIDUMP_TYPE.MiniDumpNormal |
                    MINIDUMP_TYPE.MiniDumpWithUnloadedModules |
                    MINIDUMP_TYPE.MiniDumpWithHandleData |
                    MINIDUMP_TYPE.MiniDumpWithThreadInfo |
                    MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo |
                    MINIDUMP_TYPE.MiniDumpWithPrivateReadWriteMemory |
                    MINIDUMP_TYPE.MiniDumpWithDataSegs |
                    MINIDUMP_TYPE.MiniDumpScanMemory |
                    MINIDUMP_TYPE.MiniDumpWithTokenInformation;

                using var fs = new FileStream(dumpPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
                bool ok = MiniDumpWriteDump(
                    process.Handle,
                    process.Id,
                    fs.SafeFileHandle,
                    flags,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!ok)
                {
                    int lastError = Marshal.GetLastWin32Error();
                    error = $"MiniDumpWriteDump failed. Win32Error={lastError}";
                    return false;
                }

                error = null;
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        // ------------------------------ TRIAGE MODE ------------------------------

        private static void RunTriage(string dumpPath, string outputFolder, bool dumpAllNonMicrosoft, bool outputJson, string? encodeKey)
        {
            Console.WriteLine($"[+] Loading dump: {dumpPath}");

            using DataTarget dataTarget = DataTarget.LoadDump(dumpPath);

            Directory.CreateDirectory(outputFolder);

            var clr = dataTarget.ClrVersions.FirstOrDefault();
            if (clr == null)
            {
                Console.WriteLine("[i] This dump does not contain a .NET CLR. Exiting.");
                return;
            }

            // Detect architecture mismatch early.
            // Note: bitness alone is not enough (ARM64 vs AMD64 are both 64-bit).
            Architecture dumpArch = dataTarget.DataReader.Architecture;
            System.Runtime.InteropServices.Architecture processArch = RuntimeInformation.ProcessArchitecture;

            // ClrMD's architecture can be ambiguous for ARM64EC dumps. Use the CLR module path as a strong hint.
            string? clrModulePath = clr.ModuleInfo.FileName;
            System.Runtime.InteropServices.Architecture? clrModuleArchHint = null;
            if (!string.IsNullOrWhiteSpace(clrModulePath))
            {
                if (clrModulePath.Contains(@"\Microsoft.NET\FrameworkArm64\", StringComparison.OrdinalIgnoreCase))
                    clrModuleArchHint = System.Runtime.InteropServices.Architecture.Arm64;
                else if (clrModulePath.Contains(@"\Microsoft.NET\Framework64\", StringComparison.OrdinalIgnoreCase))
                    clrModuleArchHint = System.Runtime.InteropServices.Architecture.X64;
                else if (clrModulePath.Contains(@"\Microsoft.NET\Framework\", StringComparison.OrdinalIgnoreCase))
                    clrModuleArchHint = System.Runtime.InteropServices.Architecture.X86;
            }

            Console.WriteLine($"[+] Host process architecture: {processArch}");
            Console.WriteLine($"[+] Dump architecture: {dumpArch}");
            if (!string.IsNullOrWhiteSpace(clrModulePath))
                Console.WriteLine($"[+] CLR module path: {clrModulePath}");
            if (clrModuleArchHint != null)
                Console.WriteLine($"[+] CLR module architecture hint: {clrModuleArchHint}");

            // ARM64EC commonly shows up as X64 in the data reader, but the CLR module path can be FrameworkArm64.
            // In that situation, ClrMD will generally behave like an X64 target (and require the x64 analysis binary).
            bool isArm64EcSuspected = dumpArch == Architecture.X64 && clrModuleArchHint == System.Runtime.InteropServices.Architecture.Arm64;
            if (isArm64EcSuspected)
            {
                Console.WriteLine("[!] ARM64EC-style dump detected (x64 context with FrameworkArm64 CLR module).");
                if (processArch == System.Runtime.InteropServices.Architecture.X64)
                    Console.WriteLine($"[!] You are running {GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture.X64)}: this can analyze the x64 context, but cannot load an ARM64 DAC.");
                else if (processArch == System.Runtime.InteropServices.Architecture.Arm64)
                    Console.WriteLine($"[!] You are running {GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture.Arm64)}: this can load ARM64 DACs, but the dump may still require an AMD64 DAC depending on how it was captured.");
            }

            System.Runtime.InteropServices.Architecture? mappedDumpArch = dumpArch switch
            {
                Architecture.X64 => System.Runtime.InteropServices.Architecture.X64,
                Architecture.X86 => System.Runtime.InteropServices.Architecture.X86,
                Architecture.Arm64 => System.Runtime.InteropServices.Architecture.Arm64,
                _ => null
            };

            System.Runtime.InteropServices.Architecture effectiveDumpArch;
            if (isArm64EcSuspected)
            {
                effectiveDumpArch = System.Runtime.InteropServices.Architecture.X64;
            }
            else if (mappedDumpArch != null)
            {
                effectiveDumpArch = mappedDumpArch.Value;
            }
            else if (clrModuleArchHint != null)
            {
                effectiveDumpArch = clrModuleArchHint.Value;
            }
            else
            {
                effectiveDumpArch = processArch;
            }

            bool archCompatible;
            if (isArm64EcSuspected)
            {
                // ARM64EC: ClrMD may report X64 while CLR module is Arm64. Allow either tool build.
                // In practice, the ARM64 build can load ARM64 DACs, and the x64 build can handle the x64 context.
                archCompatible = processArch == System.Runtime.InteropServices.Architecture.X64 ||
                                 processArch == System.Runtime.InteropServices.Architecture.Arm64;
            }
            else
            {
                archCompatible = processArch == effectiveDumpArch;
            }

            if (!archCompatible)
            {
                Console.Error.WriteLine($"[!] Run: {GetRecommendedDumperBinaryName(effectiveDumpArch)}");
                return;
            }

            Console.WriteLine($"[+] CLR: {clr.Version}, Flavor: {clr.Flavor}");
            Console.WriteLine($"[+] Architecture: {FormatDumpArchitecture(dumpArch, dataTarget.DataReader.PointerSize)}");

            // Preflight: if CLR module strongly indicates ARM64 Desktop CLR but we're the x64 build,
            // avoid the CreateRuntime failure and print actionable guidance.
            if (clrModuleArchHint == System.Runtime.InteropServices.Architecture.Arm64 &&
                RuntimeInformation.ProcessArchitecture == System.Runtime.InteropServices.Architecture.X64 &&
                clr.Flavor == ClrFlavor.Desktop)
            {
                Console.Error.WriteLine($"[!] Run: {GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture.Arm64)}");
                return;
            }

            // Managed analysis: default ClrMD runtime creation.
            ClrRuntime? runtime = null;
            try
            {
                runtime = clr.CreateRuntime();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Unable to create a managed runtime: {ex.Message}");
                Console.Error.WriteLine("[!] Skipping analysis because managed runtime initialization failed.");
                return;
            }

            using var runtimeDispose = runtime;
            ClrHeap heap = runtime.Heap;

            if (!heap.CanWalkHeap)
            {
                Console.WriteLine("[!] Warning: Heap not walkable – string extraction will be limited.");
            }

            string assembliesFolder = Path.Combine(outputFolder, "assemblies");
            Directory.CreateDirectory(assembliesFolder);

            // ---- MODULES ----
            var moduleInfo = EnumerateModules(dataTarget, runtime);
            if (outputJson)
            {
                string moduleJsonPath = Path.Combine(outputFolder, "modules.json");
                WriteModuleReportJson(moduleJsonPath, moduleInfo);
                Console.WriteLine($"[+] Module report written to: {moduleJsonPath}");
            }
            else
            {
                string moduleReportPath = Path.Combine(outputFolder, "modules.txt");
                WriteModuleReport(moduleReportPath, moduleInfo);
                Console.WriteLine($"[+] Module report written to: {moduleReportPath}");
            }

            // ---- STRINGS ----
            if (heap.CanWalkHeap)
            {
                var allStrings = ExtractManagedStringsDistinct(heap);

                string allStringsPath = Path.Combine(outputFolder, "managed_strings_all.txt");
                WriteAllStrings(allStringsPath, allStrings);
                Console.WriteLine($"[+] All managed strings written to: {allStringsPath}");

                string suspiciousStringsPath = Path.Combine(outputFolder, "managed_strings_suspicious.txt");
                WriteSuspiciousStrings(suspiciousStringsPath, allStrings);
                Console.WriteLine($"[+] Suspicious managed strings written to: {suspiciousStringsPath}");
            }

            if (outputJson)
            {
                string patchJsonPath = Path.Combine(outputFolder, "patch_detection.json");
                DetectDefensivePatches(dataTarget, runtime, null, patchJsonPath);
                Console.WriteLine($"[+] Patch detection report written to: {patchJsonPath}");
            }
            else
            {
                string patchReportPath = Path.Combine(outputFolder, "patch_detection.txt");
                DetectDefensivePatches(dataTarget, runtime, patchReportPath, null);
                Console.WriteLine($"[+] Patch detection report written to: {patchReportPath}");
            }

            // ---- DUMP MODULES (with dedupe) ----
            DumpModules(dataTarget, runtime, assembliesFolder, dumpAllNonMicrosoft, encodeKey);
            string encodingSuffix = encodeKey != null ? " (RC4 encoded)" : "";
            Console.WriteLine(dumpAllNonMicrosoft
                ? $"[+] Dynamic + non-Microsoft file-backed assemblies dumped (deduped){encodingSuffix} to: " + assembliesFolder
                : $"[+] Dynamic assemblies dumped (deduped){encodingSuffix} to: " + assembliesFolder);
        }

        private static bool IsLikelyClrProcess(int pid, out string? error)
        {
            error = null;

            try
            {
                using Process process = Process.GetProcessById(pid);
                return IsLikelyClrProcess(process, out error);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool IsLikelyClrProcess(Process process, out string? error)
        {
            error = null;

            try
            {
                // Heuristic: presence of CLR modules is usually sufficient.
                // For .NET Framework: clr.dll/mscorwks.dll/mscoree.dll
                // For .NET (Core/5+): coreclr.dll/hostfxr.dll
                foreach (ProcessModule module in process.Modules)
                {
                    string name = module.ModuleName ?? "";
                    if (name.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("mscorwks.dll", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("hostfxr.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool TryGetProcessMachineInfo(
            int pid,
            out System.Runtime.InteropServices.Architecture? processArch,
            out System.Runtime.InteropServices.Architecture? nativeArch,
            out string? error)
        {
            processArch = null;
            nativeArch = null;
            error = null;

            if (!OperatingSystem.IsWindows())
            {
                error = "IsWow64Process2 is Windows-only.";
                return false;
            }

            try
            {
                using Process process = Process.GetProcessById(pid);

                if (!IsWow64Process2(process.Handle, out ushort pm, out ushort nm))
                {
                    error = $"IsWow64Process2 failed. Win32Error={Marshal.GetLastWin32Error()}";
                    return false;
                }

                nativeArch = MapMachineToArch(nm);

                // If pm == UNKNOWN, the process is not under WOW64; treat it as native.
                processArch = pm == IMAGE_FILE_MACHINE_UNKNOWN
                    ? nativeArch
                    : MapMachineToArch(pm);

                return true;
            }
            catch (EntryPointNotFoundException)
            {
                error = "IsWow64Process2 is not available on this Windows version.";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static System.Runtime.InteropServices.Architecture? MapMachineToArch(ushort machine) =>
            machine switch
            {
                IMAGE_FILE_MACHINE_I386 => System.Runtime.InteropServices.Architecture.X86,
                IMAGE_FILE_MACHINE_AMD64 => System.Runtime.InteropServices.Architecture.X64,
                IMAGE_FILE_MACHINE_ARM64 => System.Runtime.InteropServices.Architecture.Arm64,
                _ => null
            };

        private static string GetRecommendedDumperBinaryName(System.Runtime.InteropServices.Architecture arch) =>
            arch switch
            {
                System.Runtime.InteropServices.Architecture.X86 => "DotnetDumper_x86.exe",
                System.Runtime.InteropServices.Architecture.Arm64 => "DotnetDumper_arm64.exe",
                System.Runtime.InteropServices.Architecture.X64 => "DotnetDumper.exe",
                _ => "DotnetDumper.exe"
            };

        private static bool TryGetClrModuleArchHintFromLiveProcess(
            int pid,
            out System.Runtime.InteropServices.Architecture? archHint,
            out string? clrModulePath,
            out string? error)
        {
            archHint = null;
            clrModulePath = null;
            error = null;

            try
            {
                using Process process = Process.GetProcessById(pid);

                foreach (ProcessModule module in process.Modules)
                {
                    string moduleName = module.ModuleName ?? "";
                    if (!moduleName.Equals("clr.dll", StringComparison.OrdinalIgnoreCase) &&
                        !moduleName.Equals("coreclr.dll", StringComparison.OrdinalIgnoreCase))
                        continue;

                    clrModulePath = module.FileName;
                    if (string.IsNullOrWhiteSpace(clrModulePath))
                        return true;

                    if (clrModulePath.Contains(@"\Microsoft.NET\FrameworkArm64\", StringComparison.OrdinalIgnoreCase))
                    {
                        archHint = System.Runtime.InteropServices.Architecture.Arm64;
                        return true;
                    }

                    if (clrModulePath.Contains(@"\Microsoft.NET\Framework64\", StringComparison.OrdinalIgnoreCase))
                    {
                        archHint = System.Runtime.InteropServices.Architecture.X64;
                        return true;
                    }

                    if (clrModulePath.Contains(@"\Microsoft.NET\Framework\", StringComparison.OrdinalIgnoreCase))
                    {
                        archHint = System.Runtime.InteropServices.Architecture.X86;
                        return true;
                    }

                    // Found CLR but couldn't infer arch.
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool DumpContainsClr(string dumpPath, out string? error)
        {
            error = null;

            try
            {
                using DataTarget dataTarget = DataTarget.LoadDump(dumpPath);
                return dataTarget.ClrVersions.Any();
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static void TryDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
                // best effort
            }
        }

        private static string FormatDumpArchitecture(Architecture dumpArch, int pointerSize)
        {
            return dumpArch switch
            {
                Architecture.X86 => "x86",
                Architecture.X64 => "x64",
                Architecture.Arm64 => "arm64",
                _ => pointerSize == 8 ? "64-bit" : "32-bit"
            };
        }

        // ------------------------------ MODULES ------------------------------

        private static List<ModuleRecord> EnumerateModules(DataTarget dataTarget, ClrRuntime runtime)
        {
            var records = new List<ModuleRecord>();

            // Some dump formats / CLR flavors cause ClrMD to report module sizes as 0.
            // The native module list in the dump usually has image sizes, so we use it as a fallback.
            Dictionary<ulong, long> nativeSizeByBase = new Dictionary<ulong, long>();
            Dictionary<string, long> nativeSizeByPath = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (ModuleInfo m in dataTarget.EnumerateModules())
                {
                    if (m.ImageBase != 0 && m.ImageSize > 0)
                        nativeSizeByBase[m.ImageBase] = m.ImageSize;

                    if (!string.IsNullOrWhiteSpace(m.FileName) && m.ImageSize > 0)
                        nativeSizeByPath[m.FileName] = m.ImageSize;
                }
            }
            catch
            {
                // best effort only
            }

            foreach (ClrAppDomain domain in runtime.AppDomains)
            {
                foreach (ClrModule module in domain.Modules)
                {
                    string moduleName = module.Name ?? "";
                    string assemblyName = module.AssemblyName ?? "";

                    bool hasPath = moduleName.Contains("\\") || moduleName.Contains("/");
                    bool isMicrosoft =
                        assemblyName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.StartsWith("Windows.", StringComparison.OrdinalIgnoreCase);

                    bool isDynamicOrNoFile = module.IsDynamic ||
                                             string.IsNullOrEmpty(moduleName) ||
                                             !hasPath;

                    ulong baseAddress = module.Address;
                    ulong size = (ulong)Math.Max(0, module.Size);

                    if (size == 0)
                    {
                        if (nativeSizeByBase.TryGetValue(baseAddress, out long nativeSize) && nativeSize > 0)
                            size = (ulong)nativeSize;
                        else if (!string.IsNullOrWhiteSpace(moduleName) && nativeSizeByPath.TryGetValue(moduleName, out long nativePathSize) && nativePathSize > 0)
                            size = (ulong)nativePathSize;
                    }

                    records.Add(new ModuleRecord
                    {
                        AppDomainId = domain.Id,
                        AppDomainName = domain.Name ?? "",
                        ModuleName = moduleName,
                        AssemblyName = assemblyName,
                        BaseAddress = baseAddress,
                        Size = size,
                        IsDynamic = module.IsDynamic,
                        IsMicrosoft = isMicrosoft,
                        IsDynamicOrNoFile = isDynamicOrNoFile
                    });
                }
            }

            return records
                .OrderBy(r => r.IsMicrosoft)
                .ThenByDescending(r => r.IsDynamicOrNoFile)
                .ThenBy(r => r.ModuleName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static void WriteModuleReport(string path, List<ModuleRecord> modules)
        {
            using var writer = new StreamWriter(path, append: false, encoding: Utf8NoBomSafe);

            writer.WriteLine("# .NET Module Triage");
            writer.WriteLine();

            foreach (var group in modules.GroupBy(m => m.AppDomainId).OrderBy(g => g.Key))
            {
                writer.WriteLine($"## AppDomain {group.Key} - {group.First().AppDomainName}");
                writer.WriteLine("IsMicrosoft\tIsDynamic/NoFile\tBaseAddress\tSize\tAssemblyName\tModuleName");

                foreach (var m in group)
                    writer.WriteLine(
                        $"{YN(m.IsMicrosoft)}\t{YN(m.IsDynamicOrNoFile)}\t0x{m.BaseAddress:x16}\t{m.Size}\t{m.AssemblyName}\t{m.ModuleName}");

                writer.WriteLine();
            }
        }

        private static void WriteModuleReportJson(string path, List<ModuleRecord> modules)
        {
            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            
            writer.WriteStartObject();
            writer.WriteString("generatedAt", DateTime.UtcNow.ToString("o"));
            writer.WriteNumber("totalModules", modules.Count);
            
            writer.WriteStartArray("modules");
            foreach (var m in modules)
            {
                writer.WriteStartObject();
                writer.WriteNumber("appDomainId", m.AppDomainId);
                writer.WriteString("appDomainName", m.AppDomainName);
                writer.WriteString("assemblyName", m.AssemblyName);
                writer.WriteString("moduleName", m.ModuleName);
                writer.WriteString("baseAddress", $"0x{m.BaseAddress:x16}");
                writer.WriteNumber("size", m.Size);
                writer.WriteBoolean("isDynamic", m.IsDynamic);
                writer.WriteBoolean("isMicrosoft", m.IsMicrosoft);
                writer.WriteBoolean("isDynamicOrNoFile", m.IsDynamicOrNoFile);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            
            writer.WriteEndObject();
        }

        // ------------------------------ STRINGS ------------------------------

        private static HashSet<string> ExtractManagedStringsDistinct(ClrHeap heap)
        {
            // We ultimately write sorted distinct strings, so de-dupe during heap walk
            // to reduce memory pressure and redundant work.
            var result = new HashSet<string>(StringComparer.Ordinal);

            foreach (var obj in heap.EnumerateObjects())
            {
                if (!obj.IsValid)
                    continue;

                var type = obj.Type;
                if (type == null)
                    continue;

                if (!string.Equals(type.Name, "System.String", StringComparison.Ordinal))
                    continue;

                string? value;
                try
                {
                    value = obj.AsString(4096);
                }
                catch
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(value))
                    result.Add(value);
            }

            return result;
        }

        private static void WriteAllStrings(string path, IEnumerable<string> strings)
        {
            var ordered = strings.OrderBy(s => s, StringComparer.Ordinal);

            using var writer = new StreamWriter(path, false, Utf8NoBomSafe);

            foreach (var s in ordered)
                writer.WriteLine(s);
        }

        private static IEnumerable<string> ExtractIpAddresses(string input)
        {
            foreach (Match m in Ipv4Regex.Matches(input))
            {
                string candidate = m.Value;

                if (IsPublicOrPrivateIPv4(candidate))
                    yield return candidate;
            }
        }

        private static bool IsPublicOrPrivateIPv4(string ipString)
        {
            if (!IPAddress.TryParse(ipString, out var ip))
                return false;

            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false; // only IPv4

            var b = ip.GetAddressBytes();

            // RFC1918 private ranges
            bool isPrivate =
                b[0] == 10 ||                                      // 10.0.0.0/8
                (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||       // 172.16.0.0/12
                (b[0] == 192 && b[1] == 168);                      // 192.168.0.0/16

            // Special non-public ranges we want to drop:
            bool isLoopback   = (b[0] == 127);                                         // 127.0.0.0/8
            bool isLinkLocal  = (b[0] == 169 && b[1] == 254);                          // 169.254.0.0/16
            bool isMulticast  = (b[0] >= 224 && b[0] <= 239);                          // 224.0.0.0/4
            bool isReserved   = (b[0] == 0 || b[0] >= 240);                            // 0.0.0.0/8, 240.0.0.0/4
            bool isBroadcast  = (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255); // 255.255.255.255

            bool isSpecialNonPublic = isLoopback || isLinkLocal || isMulticast || isReserved || isBroadcast;

            // "Public or private" = anything not in the special non-public ranges
            return isPrivate || !isSpecialNonPublic;
        }

        private static void WriteSuspiciousStrings(string path, IEnumerable<string> strings)
        {
            var hits = new HashSet<string>(StringComparer.Ordinal);
            var ips = new HashSet<string>(StringComparer.Ordinal);
            int benignSkipped = 0;

            foreach (string s in strings)
            {
                // Extract IPs regardless of regex match
                foreach (var ip in ExtractIpAddresses(s))
                    ips.Add(ip);

                // Must match at least one suspicious regex
                bool isSuspicious = SuspiciousRegexes.Any(re => re.IsMatch(s));
                if (!isSuspicious)
                    continue;

                string lower = s.ToLowerInvariant();

                // Skip if it matches a benign domain pattern
                if (ContainsBenignDomain(lower))
                {
                    benignSkipped++;
                    continue;
                }

                hits.Add(s);
            }

            using var writer = new StreamWriter(path, false, Utf8NoBomSafe);

            writer.WriteLine("# Suspicious managed strings (filtered)");
            writer.WriteLine("# Suspicious string count: " + hits.Count);
            writer.WriteLine("# Unique IPs extracted: " + ips.Count);
            writer.WriteLine("# Benign-domain strings excluded: " + benignSkipped);
            writer.WriteLine();

            writer.WriteLine("## Extracted IP Addresses");
            foreach (var ip in ips.OrderBy(x => x, StringComparer.Ordinal))
                writer.WriteLine(ip);

            writer.WriteLine();
            writer.WriteLine("## Suspicious Strings");
            foreach (var s in hits.OrderBy(x => x, StringComparer.Ordinal))
                writer.WriteLine(s);
        }

        private static bool ContainsBenignDomain(string lower)
        {
            foreach (var domain in BenignDomains)
            {
                if (lower.Contains(domain))
                    return true;
            }

            return false;
        }

        // -------------------------- PATCH DETECTION ----------------------------

        private static void DetectDefensivePatches(DataTarget dataTarget, ClrRuntime runtime, string? outputPath, string? jsonOutputPath)
        {
            var findings = new List<PatchFinding>();

            // Define suspicious patterns that indicate patches (x64)
            // These patterns are ONLY suspicious at function entry points, not in arbitrary code
            var suspiciousPatterns = new Dictionary<string, byte[]>
            {
                // AmsiScanBuffer patched with: mov eax, 0x80070057 (E_INVALIDARG); ret
                ["AMSI_E_INVALIDARG_Patch"] = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 },
                
                // Patched with: xor eax, eax; ret (return S_OK) - x86 encoding
                ["XOR_EAX_RET_x86"] = new byte[] { 0x31, 0xC0, 0xC3 },
                
                // Patched with: xor eax, eax; ret (return S_OK) - alternative encoding
                ["XOR_EAX_RET_Alt"] = new byte[] { 0x33, 0xC0, 0xC3 },
                
                // Patched with: xor rax, rax; ret (x64)
                ["XOR_RAX_RET_x64"] = new byte[] { 0x48, 0x31, 0xC0, 0xC3 },
                
                // Patched with: xor rax, rax; ret (x64 alternative)
                ["XOR_RAX_RET_x64_Alt"] = new byte[] { 0x48, 0x33, 0xC0, 0xC3 },
                
                // Patched with: mov eax, 1; ret
                ["MOV_EAX_1_RET"] = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 },
                
                // Hardware breakpoint patch: xor eax, eax; nop; ret
                ["XOR_EAX_NOP_RET"] = new byte[] { 0x33, 0xC0, 0x90, 0xC3 },
                
                // NOP slide (6+ NOPs is very suspicious at function start)
                ["NOP_Slide_6"] = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
                
                // Immediate return (single RET at function start is suspicious)
                // We'll handle this specially with additional context
                ["Immediate_RET"] = new byte[] { 0xC3 },
                
                // Common jmp patch for inline hooks (E9 = near jmp with 4-byte relative offset)
                ["JMP_Inline_Hook"] = new byte[] { 0xE9 }
            };

            // Define critical functions to check in each module
            var amsiTargets = new[] { "AmsiScanBuffer", "AmsiScanString" };
            var etwTargets = new[] { "EtwEventWrite", "EtwEventWriteEx", "NtTraceEvent" };

            // Search for amsi.dll, ntdll.dll, and clr.dll modules
            foreach (var module in dataTarget.DataReader.EnumerateModules())
            {
                string moduleName = Path.GetFileName(module.FileName ?? "").ToLowerInvariant();
                
                if (moduleName == "amsi.dll")
                {
                    ScanModuleExportsForPatches(dataTarget, module, suspiciousPatterns, "AMSI", amsiTargets, findings);
                }
                else if (moduleName == "ntdll.dll")
                {
                    ScanModuleExportsForPatches(dataTarget, module, suspiciousPatterns, "ETW", etwTargets, findings);
                }
                else if (moduleName == "clr.dll")
                {
                    // Detect stealthier CLR.dll-based patches (Provider Handle, Subscriber Bit, AMSI globals)
                    // Reference: https://loland.cv/posts/2025-11-27-stealthier-reflective-loading/
                    ScanClrForStealthPatches(dataTarget, module, findings);
                }
            }

            // Write findings to report
            if (outputPath != null)
            {
                WritePatchReport(outputPath, findings);
            }
            
            if (jsonOutputPath != null)
            {
                WritePatchReportJson(jsonOutputPath, findings);
            }
            
            // Console output for findings (regardless of output format)
            if (findings.Count == 0)
            {
                Console.WriteLine("[+] No AMSI/ETW patches detected");
            }
            else
            {
                foreach (var group in findings.GroupBy(f => f.Category))
                {
                    string warningMsg = group.Key switch
                    {
                        "CLR_ETW_Stealth" => $"[!] WARNING: {group.Count()} CLR.dll stealth ETW patch(es) detected!",
                        "CLR_AMSI_Stealth" => $"[!] WARNING: {group.Count()} CLR.dll stealth AMSI patch(es) detected!",
                        _ => $"[!] WARNING: {group.Count()} {group.Key} patch(es) detected!"
                    };
                    Console.WriteLine(warningMsg);
                }
            }
        }

        private static void ScanModuleExportsForPatches(DataTarget dataTarget, ModuleInfo module,
            Dictionary<string, byte[]> patterns, string category, string[] targetFunctions, List<PatchFinding> findings)
        {
            try
            {
                ulong moduleBase = module.ImageBase;
                ulong moduleSize = (ulong)module.IndexFileSize;

                if (moduleSize == 0 || moduleSize > 50 * 1024 * 1024)
                    return;

                byte[] moduleBytes = new byte[moduleSize];
                int read = dataTarget.DataReader.Read(moduleBase, moduleBytes);

                if (read <= 0)
                    return;

                // Parse PE exports to find target functions
                var exports = ParsePeExports(moduleBytes, read);
                
                if (exports.Count == 0)
                {
                    Console.WriteLine($"[i] No exports found in {Path.GetFileName(module.FileName)}, skipping patch detection");
                    return;
                }

                // Check each target function
                foreach (var targetFunc in targetFunctions)
                {
                    if (!exports.TryGetValue(targetFunc, out uint rva))
                        continue;

                    // Scan first 32 bytes of function for suspicious patterns
                    int offset = (int)rva;
                    if (offset < 0 || offset >= read)
                        continue;

                    int scanLength = Math.Min(32, read - offset);
                    byte[] functionBytes = new byte[scanLength];
                    Array.Copy(moduleBytes, offset, functionBytes, 0, scanLength);

                    // Check each pattern
                    foreach (var kvp in patterns)
                    {
                        string patternName = kvp.Key;
                        byte[] pattern = kvp.Value;

                        if (pattern.Length > scanLength)
                            continue;

                        // For single RET (0xC3), only flag if it's the FIRST instruction
                        if (patternName == "Immediate_RET")
                        {
                            if (functionBytes[0] == 0xC3)
                            {
                                findings.Add(CreatePatchFinding(category, module, moduleBase, targetFunc, patternName, offset, pattern));
                            }
                            continue;
                        }

                        // For JMP hook, only flag if it's the FIRST instruction
                        if (patternName == "JMP_Inline_Hook")
                        {
                            if (functionBytes[0] == 0xE9)
                            {
                                findings.Add(CreatePatchFinding(category, module, moduleBase, targetFunc, patternName, offset, pattern));
                            }
                            continue;
                        }

                        // For other patterns, check if they appear within first few bytes
                        for (int i = 0; i <= scanLength - pattern.Length; i++)
                        {
                            bool match = true;
                            for (int j = 0; j < pattern.Length; j++)
                            {
                                if (functionBytes[i + j] != pattern[j])
                                {
                                    match = false;
                                    break;
                                }
                            }

                            if (match)
                            {
                                findings.Add(CreatePatchFinding(category, module, moduleBase, targetFunc, patternName, offset + i, pattern));
                                break; // Only report first match per pattern per function
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Error scanning {module.FileName}: {ex.Message}");
            }
        }

        /// <summary>
        /// Detects stealthier CLR.dll-based ETW/AMSI bypasses that don't require memory protection changes.
        /// These patches target writable .data section globals in clr.dll:
        /// 1. Provider Handle Patching - Microsoft_Windows_DotNETRuntimeHandle set to 1 (crash-avoidance value)
        /// 2. CLR AMSI Patching - amsiScanBuffer/g_amsiContext tampered
        /// Reference: https://loland.cv/posts/2025-11-27-stealthier-reflective-loading/
        /// 
        /// NOTE: We do NOT check EnableBits=0 because that's the normal state when no ETW consumer is subscribed.
        /// </summary>
        private static void ScanClrForStealthPatches(DataTarget dataTarget, ModuleInfo module, List<PatchFinding> findings)
        {
            try
            {
                ulong moduleBase = module.ImageBase;
                ulong moduleSize = (ulong)module.IndexFileSize;

                if (moduleSize == 0 || moduleSize > 50 * 1024 * 1024)
                    return;

                byte[] moduleBytes = new byte[moduleSize];
                int read = dataTarget.DataReader.Read(moduleBase, moduleBytes);

                if (read <= 0)
                    return;

                // 1. Detect Provider Handle Patching
                // Pattern: mov rcx, qword ptr [Microsoft_Windows_DotNETRuntimeHandle] ; call CoTemplate_*
                // Signature: 48 8b 0d ?? ?? ?? ?? e8 (mov rcx, [rip+offset]; call rel32)
                // 
                // A handle value of 1 is the attacker's crash-avoidance value (0 would crash in some ETW paths)
                // A valid handle is typically a large pointer value like 0x7e0cc620
                var handleAddresses = new Dictionary<ulong, int>();
                for (int i = 0; i < read - 12; i++)
                {
                    // Look for: 48 8b 0d XX XX XX XX e8 (mov rcx, [rip+??]; call ??)
                    if (moduleBytes[i] == 0x48 && moduleBytes[i + 1] == 0x8b && moduleBytes[i + 2] == 0x0d &&
                        moduleBytes[i + 7] == 0xe8)
                    {
                        // Calculate the global variable address from RIP-relative offset
                        int offset = BitConverter.ToInt32(moduleBytes, i + 3);
                        ulong rip = moduleBase + (ulong)(i + 7); // RIP after the mov instruction
                        ulong handleAddr = (ulong)((long)rip + offset);

                        // Verify it points within the module's .data section (rough check)
                        if (handleAddr > moduleBase && handleAddr < moduleBase + (ulong)read)
                        {
                            if (!handleAddresses.ContainsKey(handleAddr))
                                handleAddresses[handleAddr] = 0;
                            handleAddresses[handleAddr]++;
                        }
                    }
                }

                // The most frequently referenced handle is likely Microsoft_Windows_DotNETRuntimeHandle
                if (handleAddresses.Count > 0)
                {
                    var mostCommonHandle = handleAddresses.OrderByDescending(kv => kv.Value).First();
                    ulong handleAddr = mostCommonHandle.Key;
                    int handleOffset = (int)(handleAddr - moduleBase);

                    if (handleOffset >= 0 && handleOffset + 8 <= read)
                    {
                        long handleValue = BitConverter.ToInt64(moduleBytes, handleOffset);

                        // Only flag handle value of 1 - this is the specific crash-avoidance value attackers use
                        // Value 0 could be normal (provider not yet registered or no .NET activity yet)
                        // Valid handles are large pointer values (e.g., 0x7e0cc620)
                        if (handleValue == 1)
                        {
                            findings.Add(new PatchFinding
                            {
                                Category = "CLR_ETW_Stealth",
                                ModuleName = module.FileName ?? "clr.dll",
                                ModuleBase = moduleBase,
                                FunctionName = "Microsoft_Windows_DotNETRuntimeHandle",
                                PatchType = "ProviderHandle_CrashAvoidance",
                                Offset = handleOffset,
                                Address = handleAddr,
                                Pattern = $"Value: 0x{handleValue:X16} (attack value to avoid NULL crashes)"
                            });
                        }
                    }
                }

                // NOTE: We intentionally do NOT check EnableBits = 0 
                // EnableBits = 0 is the NORMAL state when no ETW consumer (logman, EDR, etc.) is subscribed
                // Attackers patch it to 0, but it's also 0 most of the time naturally = too many false positives

                // 2. Detect CLR AMSI Patching (amsiScanBuffer/g_amsiContext globals)
                // Attack flow from clr!AmsiScan:
                //   if (!g_amsiContext && !is_amsi_initialized) { // initialize AMSI }
                //   amsiScanBuffer(g_amsiContext, malicious_assembly);
                //
                // To bypass: set g_amsiContext=1 (skip init), set amsiScanBuffer=fakeFunc (return 1 = scan failed)
                //
                // Signature to find these globals:
                //   lea rdx, "AmsiScanBuffer"    ; 48 8d 15 ?? ?? ?? ??
                //   call GetProcAddress          ; ff 15 ?? ?? ?? ??
                //   mov [amsiScanBuffer], rax    ; 48 89 ?? ?? ?? ?? ??
                //   mov r??, [g_amsiContext]     ; 48 8b ?? ?? ?? ?? ??
                
                // Get amsi.dll address range to check if amsiScanBuffer points inside it
                ulong amsiDllBase = 0, amsiDllEnd = 0;
                foreach (var mod in dataTarget.DataReader.EnumerateModules())
                {
                    if (Path.GetFileName(mod.FileName ?? "").Equals("amsi.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        amsiDllBase = mod.ImageBase;
                        amsiDllEnd = mod.ImageBase + (ulong)mod.IndexFileSize;
                        break;
                    }
                }

                for (int i = 0; i < read - 30; i++)
                {
                    // Look for: 48 8d 15 (lea rdx, [rip+??])
                    if (moduleBytes[i] == 0x48 && moduleBytes[i + 1] == 0x8d && moduleBytes[i + 2] == 0x15)
                    {
                        int leaOffset = BitConverter.ToInt32(moduleBytes, i + 3);
                        ulong leaRip = moduleBase + (ulong)(i + 7);
                        ulong stringAddr = (ulong)((long)leaRip + leaOffset);

                        // Check if this points to "AmsiScanBuffer" string
                        int stringOffset = (int)(stringAddr - moduleBase);
                        if (stringOffset >= 0 && stringOffset + 14 <= read)
                        {
                            string potentialString = Encoding.ASCII.GetString(moduleBytes, stringOffset, 14);
                            if (potentialString == "AmsiScanBuffer")
                            {
                                // Found the AMSI code! Now find the global variables
                                // Search forward for: ff 15 (call GetProcAddress)
                                for (int j = i + 7; j < Math.Min(i + 50, read - 14); j++)
                                {
                                    if (moduleBytes[j] == 0xff && moduleBytes[j + 1] == 0x15)
                                    {
                                        // After GetProcAddress call, look for mov [amsiScanBuffer], rax
                                        for (int k = j + 6; k < Math.Min(j + 20, read - 11); k++)
                                        {
                                            // 48 89 05/0d/15/1d/25/2d/35/3d = mov [rip+??], rax/rcx/rdx/rbx/rsp/rbp/rsi/rdi
                                            if (moduleBytes[k] == 0x48 && moduleBytes[k + 1] == 0x89 && 
                                                (moduleBytes[k + 2] & 0xC7) == 0x05) // ModRM for [rip+disp32]
                                            {
                                                int movOffset = BitConverter.ToInt32(moduleBytes, k + 3);
                                                ulong movRip = moduleBase + (ulong)(k + 7);
                                                ulong amsiScanBufferAddr = (ulong)((long)movRip + movOffset);

                                                int amsiScanBufferOffset = (int)(amsiScanBufferAddr - moduleBase);
                                                if (amsiScanBufferOffset >= 0 && amsiScanBufferOffset + 8 <= read)
                                                {
                                                    ulong amsiScanBufferValue = BitConverter.ToUInt64(moduleBytes, amsiScanBufferOffset);

                                                    // Suspicious if:
                                                    // 1. Small value like 1 (pre-set to skip initialization)
                                                    // 2. Non-zero but NOT pointing inside amsi.dll (fake function)
                                                    bool isSmallValue = (amsiScanBufferValue >= 1 && amsiScanBufferValue <= 0xFFFF);
                                                    bool isOutsideAmsi = (amsiScanBufferValue != 0 && 
                                                                          amsiDllBase != 0 && 
                                                                          (amsiScanBufferValue < amsiDllBase || amsiScanBufferValue >= amsiDllEnd));

                                                    if (isSmallValue)
                                                    {
                                                        findings.Add(new PatchFinding
                                                        {
                                                            Category = "CLR_AMSI_Stealth",
                                                            ModuleName = module.FileName ?? "clr.dll",
                                                            ModuleBase = moduleBase,
                                                            FunctionName = "amsiScanBuffer",
                                                            PatchType = "AmsiScanBuffer_SmallValue",
                                                            Offset = amsiScanBufferOffset,
                                                            Address = amsiScanBufferAddr,
                                                            Pattern = $"Value: 0x{amsiScanBufferValue:X16} (pre-set to skip GetProcAddress)"
                                                        });
                                                    }
                                                    else if (isOutsideAmsi)
                                                    {
                                                        findings.Add(new PatchFinding
                                                        {
                                                            Category = "CLR_AMSI_Stealth",
                                                            ModuleName = module.FileName ?? "clr.dll",
                                                            ModuleBase = moduleBase,
                                                            FunctionName = "amsiScanBuffer",
                                                            PatchType = "AmsiScanBuffer_FakeFunction",
                                                            Offset = amsiScanBufferOffset,
                                                            Address = amsiScanBufferAddr,
                                                            Pattern = $"Value: 0x{amsiScanBufferValue:X16} (points outside amsi.dll!)"
                                                        });
                                                    }
                                                }

                                                // Look for g_amsiContext reference (usually within next ~20 bytes)
                                                for (int m = k + 7; m < Math.Min(k + 30, read - 11); m++)
                                                {
                                                    // 48 8b ?? = mov r64, [rip+??]
                                                    if (moduleBytes[m] == 0x48 && moduleBytes[m + 1] == 0x8b &&
                                                        (moduleBytes[m + 2] & 0xC7) == 0x05) // ModRM for [rip+disp32]
                                                    {
                                                        int ctxOffset = BitConverter.ToInt32(moduleBytes, m + 3);
                                                        ulong ctxRip = moduleBase + (ulong)(m + 7);
                                                        ulong amsiContextAddr = (ulong)((long)ctxRip + ctxOffset);

                                                        int amsiContextOffset = (int)(amsiContextAddr - moduleBase);
                                                        if (amsiContextOffset >= 0 && amsiContextOffset + 8 <= read &&
                                                            amsiContextOffset != amsiScanBufferOffset)
                                                        {
                                                            ulong amsiContextValue = BitConverter.ToUInt64(moduleBytes, amsiContextOffset);

                                                            // g_amsiContext set to small non-zero value (like 1) to skip initialization
                                                            // Normal values: 0 (not init) or valid AMSI handle pointer
                                                            if (amsiContextValue >= 1 && amsiContextValue <= 0xFFFF)
                                                            {
                                                                findings.Add(new PatchFinding
                                                                {
                                                                    Category = "CLR_AMSI_Stealth",
                                                                    ModuleName = module.FileName ?? "clr.dll",
                                                                    ModuleBase = moduleBase,
                                                                    FunctionName = "g_amsiContext",
                                                                    PatchType = "AmsiContext_FakeInit",
                                                                    Offset = amsiContextOffset,
                                                                    Address = amsiContextAddr,
                                                                    Pattern = $"Value: 0x{amsiContextValue:X16} (fake value to skip AMSI init)"
                                                                });
                                                            }
                                                        }
                                                        break;
                                                    }
                                                }
                                                goto FoundAmsiPattern;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                FoundAmsiPattern:;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Error scanning clr.dll for stealth patches: {ex.Message}");
            }
        }

        private static PatchFinding CreatePatchFinding(string category, ModuleInfo module, ulong moduleBase,
            string functionName, string patternName, int offset, byte[] pattern)
        {
            return new PatchFinding
            {
                Category = category,
                ModuleName = module.FileName ?? "unknown",
                ModuleBase = moduleBase,
                FunctionName = functionName,
                PatchType = patternName,
                Offset = offset,
                Address = moduleBase + (ulong)offset,
                Pattern = BitConverter.ToString(pattern).Replace("-", " ")
            };
        }

        private static Dictionary<string, uint> ParsePeExports(byte[] moduleBytes, int size)
        {
            var exports = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);

            try
            {
                // Verify DOS header
                if (size < 64 || moduleBytes[0] != 0x4D || moduleBytes[1] != 0x5A)
                    return exports;

                // Get PE header offset
                int peOffset = BitConverter.ToInt32(moduleBytes, 0x3C);
                if (peOffset < 0 || peOffset + 24 > size)
                    return exports;

                // Verify PE signature
                if (moduleBytes[peOffset] != 0x50 || moduleBytes[peOffset + 1] != 0x45)
                    return exports;

                // Determine if PE32 or PE32+ and get optional header offset
                int optHeaderOffset = peOffset + 24;
                if (optHeaderOffset + 2 > size)
                    return exports;

                ushort magic = BitConverter.ToUInt16(moduleBytes, optHeaderOffset);
                bool isPe32Plus = (magic == 0x20B);

                // Get export directory RVA and size
                int exportDirOffset = optHeaderOffset + (isPe32Plus ? 112 : 96);
                if (exportDirOffset + 8 > size)
                    return exports;

                uint exportDirRva = BitConverter.ToUInt32(moduleBytes, exportDirOffset);
                uint exportDirSize = BitConverter.ToUInt32(moduleBytes, exportDirOffset + 4);

                if (exportDirRva == 0 || exportDirSize == 0)
                    return exports;

                // Parse export directory
                int exportTableOffset = (int)exportDirRva;
                if (exportTableOffset + 40 > size)
                    return exports;

                uint numberOfNames = BitConverter.ToUInt32(moduleBytes, exportTableOffset + 24);
                uint addressTableRva = BitConverter.ToUInt32(moduleBytes, exportTableOffset + 28);
                uint namePointerRva = BitConverter.ToUInt32(moduleBytes, exportTableOffset + 32);
                uint ordinalTableRva = BitConverter.ToUInt32(moduleBytes, exportTableOffset + 36);

                // Read export names and addresses
                for (uint i = 0; i < numberOfNames && i < 10000; i++)
                {
                    int nameRvaOffset = (int)(namePointerRva + i * 4);
                    if (nameRvaOffset + 4 > size)
                        break;

                    uint nameRva = BitConverter.ToUInt32(moduleBytes, nameRvaOffset);
                    if (nameRva >= size)
                        continue;

                    // Read null-terminated export name
                    int nameOffset = (int)nameRva;
                    int nameEnd = nameOffset;
                    while (nameEnd < size && moduleBytes[nameEnd] != 0)
                        nameEnd++;

                    if (nameEnd >= size)
                        continue;

                    string name = Encoding.ASCII.GetString(moduleBytes, nameOffset, nameEnd - nameOffset);

                    // Get ordinal and function RVA
                    int ordinalOffset = (int)(ordinalTableRva + i * 2);
                    if (ordinalOffset + 2 > size)
                        continue;

                    ushort ordinal = BitConverter.ToUInt16(moduleBytes, ordinalOffset);
                    int funcRvaOffset = (int)(addressTableRva + ordinal * 4);
                    if (funcRvaOffset + 4 > size)
                        continue;

                    uint funcRva = BitConverter.ToUInt32(moduleBytes, funcRvaOffset);
                    exports[name] = funcRva;
                }
            }
            catch
            {
                // Return whatever we parsed successfully
            }

            return exports;
        }

        private static void WritePatchReport(string path, List<PatchFinding> findings)
        {
            using var writer = new StreamWriter(path, false, Utf8NoBomSafe);

            writer.WriteLine("# AMSI/ETW Patch Detection Report");
            writer.WriteLine($"# Total findings: {findings.Count}");
            writer.WriteLine("# Detection methods:");
            writer.WriteLine("#   - Export-based function scanning (amsi.dll, ntdll.dll)");
            writer.WriteLine("#   - CLR.dll stealth patch detection (Provider Handle, Subscriber Bit, AMSI globals)");
            writer.WriteLine("#   Reference: https://loland.cv/posts/2025-11-27-stealthier-reflective-loading/");
            writer.WriteLine();

            if (findings.Count == 0)
            {
                writer.WriteLine("No AMSI or ETW patches detected.");
                return;
            }

            // Group by category
            var groupedFindings = findings.GroupBy(f => f.Category).OrderBy(g => g.Key);

            foreach (var group in groupedFindings)
            {
                string categoryDescription = group.Key switch
                {
                    "CLR_ETW_Stealth" => "CLR.dll ETW Stealth Patches (No VirtualProtect Required)",
                    "CLR_AMSI_Stealth" => "CLR.dll AMSI Stealth Patches (No VirtualProtect Required)",
                    _ => $"{group.Key} Patches Detected"
                };

                writer.WriteLine($"## {categoryDescription}");
                writer.WriteLine();
                writer.WriteLine("Module\tFunction\tPatch Type\tAddress\tOffset\tPattern");

                foreach (var finding in group.OrderBy(f => f.Address))
                {
                    string moduleName = Path.GetFileName(finding.ModuleName);
                    string funcName = finding.FunctionName ?? "unknown";
                    writer.WriteLine($"{moduleName}\t{funcName}\t{finding.PatchType}\t0x{finding.Address:X16}\t0x{finding.Offset:X8}\t{finding.Pattern}");
                }

                writer.WriteLine();
            }
        }

        private static void WritePatchReportJson(string path, List<PatchFinding> findings)
        {
            using var stream = new FileStream(path, FileMode.Create, FileAccess.Write);
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
            
            writer.WriteStartObject();
            writer.WriteString("generatedAt", DateTime.UtcNow.ToString("o"));
            writer.WriteNumber("totalFindings", findings.Count);
            
            writer.WriteStartArray("detectionMethods");
            writer.WriteStringValue("Export-based function scanning (amsi.dll, ntdll.dll)");
            writer.WriteStringValue("CLR.dll stealth patch detection (Provider Handle, AMSI globals)");
            writer.WriteEndArray();
            
            writer.WriteString("reference", "https://loland.cv/posts/2025-11-27-stealthier-reflective-loading/");
            
            writer.WriteStartArray("findings");
            foreach (var f in findings)
            {
                writer.WriteStartObject();
                writer.WriteString("category", f.Category);
                writer.WriteString("module", Path.GetFileName(f.ModuleName));
                writer.WriteString("modulePath", f.ModuleName);
                writer.WriteString("moduleBase", $"0x{f.ModuleBase:X16}");
                writer.WriteString("functionName", f.FunctionName);
                writer.WriteString("patchType", f.PatchType);
                writer.WriteString("address", $"0x{f.Address:X16}");
                writer.WriteString("offset", $"0x{f.Offset:X8}");
                writer.WriteString("pattern", f.Pattern);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            
            writer.WriteEndObject();
        }

        // -------------------------- DUMP MODULES ----------------------------

        private static void DumpModules(DataTarget dataTarget, ClrRuntime runtime, string assembliesFolder, bool dumpAllNonMicrosoft, string? encodeKey)
        {
            foreach (ClrAppDomain domain in runtime.AppDomains)
            {
                foreach (ClrModule module in domain.Modules)
                {
                    string moduleName = module.Name ?? "";
                    string assemblyName = module.AssemblyName ?? "";

                    bool hasPath = moduleName.Contains("\\") || moduleName.Contains("/");
                    bool isMicrosoft =
                        assemblyName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.Equals("mscorlib", StringComparison.OrdinalIgnoreCase) ||
                        assemblyName.StartsWith("Windows.", StringComparison.OrdinalIgnoreCase);

                    bool isDynamicOrNoFile = module.IsDynamic ||
                                             string.IsNullOrEmpty(moduleName) ||
                                             !hasPath;

                    bool shouldDump;
                    if (dumpAllNonMicrosoft)
                    {
                        // Dump dynamic/no-file + non-Microsoft
                        shouldDump = isDynamicOrNoFile || !isMicrosoft;
                    }
                    else
                    {
                        // Default: only dynamic/no-file modules
                        shouldDump = isDynamicOrNoFile;
                    }

                    if (!shouldDump)
                        continue;

                    try
                    {
                        DumpModule(dataTarget, module, assembliesFolder, encodeKey);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[!] Failed to dump module {assemblyName ?? moduleName}: {ex.Message}");
                    }
                }
            }
        }

        private static void DumpModule(DataTarget dataTarget, ClrModule module, string assembliesFolder, string? encodeKey)
        {
            ulong sizeU = module.Size;
            if (sizeU == 0 || sizeU > int.MaxValue)
                return;

            int size = (int)sizeU;
            byte[] buffer = new byte[size];

            int read = dataTarget.DataReader.Read(module.ImageBase, buffer);
            if (read <= 0)
                return;

            if (read != buffer.Length)
            {
                var trimmed = new byte[read];
                Buffer.BlockCopy(buffer, 0, trimmed, 0, read);
                buffer = trimmed;
            }

            // Compute SHA256 hash for dedupe
            string hashHex;
            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(buffer);
                hashHex = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }

            string asmName = module.AssemblyName ?? "";
            string filePathFromModule = module.Name ?? "";

            // Base name selection
            string baseName;
            bool nameHasPath = !string.IsNullOrEmpty(filePathFromModule) &&
                               (filePathFromModule.Contains("\\") || filePathFromModule.Contains("/"));

            if (nameHasPath)
            {
                baseName = Path.GetFileNameWithoutExtension(filePathFromModule);
            }
            else if (!string.IsNullOrEmpty(asmName))
            {
                int commaIdx = asmName.IndexOf(',');
                if (commaIdx > 0)
                {
                    baseName = asmName.Substring(0, commaIdx);
                }
                else if (asmName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         asmName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         asmName.Contains("\\") || asmName.Contains("/"))
                {
                    baseName = Path.GetFileNameWithoutExtension(asmName);
                }
                else
                {
                    baseName = asmName;
                }
            }
            else if (!string.IsNullOrEmpty(filePathFromModule))
            {
                baseName = Path.GetFileNameWithoutExtension(filePathFromModule);
            }
            else
            {
                baseName = "unknown";
            }

            string key = baseName;

            if (!AssemblyHashes.TryGetValue(key, out var hashList))
            {
                hashList = new List<string>();
                AssemblyHashes[key] = hashList;
            }

            // If we've already seen this exact binary for this base name, skip it
            if (hashList.Contains(hashHex, StringComparer.OrdinalIgnoreCase))
            {
                Console.WriteLine($"[i] Skipping duplicate assembly for {baseName} (same SHA256).");
                return;
            }

            bool isFirstVariant = hashList.Count == 0;
            hashList.Add(hashHex);

            // Determine .exe vs .dll from PE header (ignoring fake 'extensions' from display names)
            string extension = encodeKey != null ? ".bin" : DeterminePeExtension(buffer, filePathFromModule);

            string safeBaseName = SanitizeFileName(baseName);

            string fileName;
            if (isFirstVariant)
            {
                fileName = $"{safeBaseName}{extension}";
            }
            else
            {
                fileName = $"{safeBaseName}_{module.ImageBase:x16}{extension}";
            }

            byte[] dataToWrite = encodeKey != null ? Rc4(buffer, Encoding.UTF8.GetBytes(encodeKey)) : buffer;

            string fullPath = Path.Combine(assembliesFolder, fileName);
            File.WriteAllBytes(fullPath, dataToWrite);

            string encodeNote = encodeKey != null ? " [RC4 encoded]" : "";
            Console.WriteLine($"[+] Dumped assembly: {fileName}{encodeNote}");
        }

        private static string DeterminePeExtension(byte[] buffer, string filePathFromModule)
        {
            // 1) Only trust module.Name if it looks like a real file path or simple filename
            //    WITHOUT commas (to avoid treating assembly display names as paths).
            if (!string.IsNullOrEmpty(filePathFromModule) && !filePathFromModule.Contains(","))
            {
                string lower = filePathFromModule.ToLowerInvariant();
                bool looksLikePath = filePathFromModule.Contains("\\") || filePathFromModule.Contains("/");
                bool looksLikeDllOrExe =
                    lower.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    lower.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

                if (looksLikePath || looksLikeDllOrExe)
                {
                    var ext = Path.GetExtension(filePathFromModule);
                    if (!string.IsNullOrEmpty(ext) &&
                        (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                         ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
                    {
                        return ext.ToLowerInvariant();
                    }
                }
            }

            // 2) Try to detect from the in-memory PE header.
            try
            {
                if (buffer.Length < 0x40)
                    return ".dll";

                if (buffer[0] != 'M' || buffer[1] != 'Z')
                    return ".dll";

                int e_lfanew = BitConverter.ToInt32(buffer, 0x3C);
                if (e_lfanew <= 0 || e_lfanew + 0x18 >= buffer.Length)
                    return ".dll";

                if (buffer[e_lfanew] != 'P' || buffer[e_lfanew + 1] != 'E' ||
                    buffer[e_lfanew + 2] != 0 || buffer[e_lfanew + 3] != 0)
                {
                    return ".dll";
                }

                int characteristicsOffset = e_lfanew + 4 + 18;
                if (characteristicsOffset + 1 >= buffer.Length)
                    return ".dll";

                const ushort IMAGE_FILE_DLL = 0x2000;
                ushort characteristics = BitConverter.ToUInt16(buffer, characteristicsOffset);

                bool isDll = (characteristics & IMAGE_FILE_DLL) != 0;
                return isDll ? ".dll" : ".exe";
            }
            catch
            {
                return ".dll";
            }
        }

        private static string SanitizeFileName(string name)
        {
            if (string.IsNullOrEmpty(name))
                return "unknown";

            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');

            return name;
        }

        // ------------------------------ TYPES ------------------------------

        private sealed class ModuleRecord
        {
            public int AppDomainId { get; set; }
            public string AppDomainName { get; set; } = "";
            public string ModuleName { get; set; } = "";
            public string AssemblyName { get; set; } = "";
            public ulong BaseAddress { get; set; }
            public ulong Size { get; set; }
            public bool IsDynamic { get; set; }
            public bool IsMicrosoft { get; set; }
            public bool IsDynamicOrNoFile { get; set; }
        }

        private sealed class PatchFinding
        {
            public string Category { get; set; } = "";
            public string ModuleName { get; set; } = "";
            public ulong ModuleBase { get; set; }
            public string FunctionName { get; set; } = "";
            public string PatchType { get; set; } = "";
            public int Offset { get; set; }
            public ulong Address { get; set; }
            public string Pattern { get; set; } = "";
        }

        private static string YN(bool b) => b ? "Y" : "N";

        // ------------------------------ RC4 ------------------------------

        /// <summary>
        /// Simple RC4 stream cipher. Same function encodes and decodes.
        /// </summary>
        private static byte[] Rc4(byte[] data, byte[] key)
        {
            // Key-scheduling algorithm (KSA)
            byte[] S = new byte[256];
            for (int i = 0; i < 256; i++)
                S[i] = (byte)i;

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % key.Length]) & 0xFF;
                (S[i], S[j]) = (S[j], S[i]);
            }

            // Pseudo-random generation algorithm (PRGA)
            byte[] result = new byte[data.Length];
            int x = 0, y = 0;
            for (int k = 0; k < data.Length; k++)
            {
                x = (x + 1) & 0xFF;
                y = (y + S[x]) & 0xFF;
                (S[x], S[y]) = (S[y], S[x]);
                byte keystreamByte = S[(S[x] + S[y]) & 0xFF];
                result[k] = (byte)(data[k] ^ keystreamByte);
            }

            return result;
        }
    }
}
