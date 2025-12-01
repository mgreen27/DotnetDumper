using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Net;
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
            string dumpPath;
            string? outputFolder = null;

            // Args:
            //  DotnetDumper <dumpPath>
            //  DotnetDumper <dumpPath> <outputFolder>
            //  DotnetDumper <dumpPath> --dump-all
            //  DotnetDumper <dumpPath> <outputFolder> --dump-all
            dumpPath = args[0];

            if (args.Length >= 2)
            {
                if (IsDumpAllFlag(args[1]))
                    dumpAllNonMicrosoft = true;
                else
                    outputFolder = args[1];
            }

            if (args.Length >= 3)
            {
                if (IsDumpAllFlag(args[2]))
                    dumpAllNonMicrosoft = true;
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
                RunTriage(dumpPath, outputFolder, dumpAllNonMicrosoft);
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

        private static void PrintUsage()
        {
            Console.WriteLine("Usage:");
            Console.WriteLine("  DotnetDumper <dumpPath> [outputFolder] [--dump-all]");
            Console.WriteLine();
            Console.WriteLine("Examples:");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp C:\\analysis\\w3wp");
            Console.WriteLine("  DotnetDumper C:\\dumps\\w3wp.dmp --dump-all");
        }

        private static void RunTriage(string dumpPath, string outputFolder, bool dumpAllNonMicrosoft)
        {
            Console.WriteLine($"[+] Loading dump: {dumpPath}");

            using DataTarget dataTarget = DataTarget.LoadDump(dumpPath);

            var clr = dataTarget.ClrVersions.FirstOrDefault();
            if (clr == null)
            {
                Console.WriteLine("[!] This dump does not contain a .NET CLR.");
                return;
            }

            using ClrRuntime runtime = clr.CreateRuntime();
            ClrHeap heap = runtime.Heap;

            Console.WriteLine($"[+] CLR: {clr.Version}, Flavor: {clr.Flavor}");
            Console.WriteLine($"[+] Architecture: {(dataTarget.DataReader.PointerSize == 8 ? "x64" : "x86")}");

            if (!heap.CanWalkHeap)
            {
                Console.WriteLine("[!] Warning: Heap not walkable – string extraction will be limited.");
            }

            string assembliesFolder = Path.Combine(outputFolder, "assemblies");
            Directory.CreateDirectory(assembliesFolder);

            // ---- MODULES ----
            var moduleInfo = EnumerateModules(runtime);
            string moduleReportPath = Path.Combine(outputFolder, "modules.txt");
            WriteModuleReport(moduleReportPath, moduleInfo);
            Console.WriteLine($"[+] Module report written to: {moduleReportPath}");

            // ---- STRINGS ----
            if (heap.CanWalkHeap)
            {
                var allStrings = ExtractManagedStrings(heap);

                string allStringsPath = Path.Combine(outputFolder, "managed_strings_all.txt");
                WriteAllStrings(allStringsPath, allStrings);
                Console.WriteLine($"[+] All managed strings written to: {allStringsPath}");

                string suspiciousStringsPath = Path.Combine(outputFolder, "managed_strings_suspicious.txt");
                WriteSuspiciousStrings(suspiciousStringsPath, allStrings);
                Console.WriteLine($"[+] Suspicious managed strings written to: {suspiciousStringsPath}");
            }

            string patchReportPath = Path.Combine(outputFolder, "patch_detection.txt");
            DetectDefensivePatches(dataTarget, runtime, patchReportPath);
            Console.WriteLine($"[+] Patch detection report written to: {patchReportPath}");

            // ---- DUMP MODULES (with dedupe) ----
            DumpModules(dataTarget, runtime, assembliesFolder, dumpAllNonMicrosoft);
            Console.WriteLine(dumpAllNonMicrosoft
                ? "[+] Dynamic + non-Microsoft file-backed assemblies dumped (deduped) to: " + assembliesFolder
                : "[+] Dynamic assemblies dumped (deduped) to: " + assembliesFolder);
        }

        // ------------------------------ MODULES ------------------------------

        private static List<ModuleRecord> EnumerateModules(ClrRuntime runtime)
        {
            var records = new List<ModuleRecord>();

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

                    records.Add(new ModuleRecord
                    {
                        AppDomainId = domain.Id,
                        AppDomainName = domain.Name ?? "",
                        ModuleName = moduleName,
                        AssemblyName = assemblyName,
                        BaseAddress = module.Address,
                        Size = (ulong)module.Size,
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

        // ------------------------------ STRINGS ------------------------------

        private static List<string> ExtractManagedStrings(ClrHeap heap)
        {
            var result = new List<string>(capacity: 50_000);

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

        private static void WriteAllStrings(string path, List<string> strings)
        {
            var distinct = strings
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal);

            using var writer = new StreamWriter(path, false, Utf8NoBomSafe);

            foreach (var s in distinct)
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

        private static void WriteSuspiciousStrings(string path, List<string> strings)
        {
            var hits = new HashSet<string>(StringComparer.Ordinal);
            var ips = new HashSet<string>(StringComparer.Ordinal);
            int benignSkipped = 0;

            foreach (string s in strings)
            {
                string lower = s.ToLowerInvariant();

                // Extract IPs regardless of regex match
                foreach (var ip in ExtractIpAddresses(s))
                    ips.Add(ip);

                // Must match at least one suspicious regex
                bool isSuspicious = SuspiciousRegexes.Any(re => re.IsMatch(s));
                if (!isSuspicious)
                    continue;

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

        private static void DetectDefensivePatches(DataTarget dataTarget, ClrRuntime runtime, string outputPath)
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

            // Search for amsi.dll and ntdll.dll modules
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
            }

            // Write findings to report
            WritePatchReport(outputPath, findings);
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
            writer.WriteLine("# Detection method: Export-based function scanning (reduces false positives)");
            writer.WriteLine();

            if (findings.Count == 0)
            {
                writer.WriteLine("No AMSI or ETW patches detected.");
                Console.WriteLine("[+] No AMSI/ETW patches detected");
                return;
            }

            // Group by category
            var groupedFindings = findings.GroupBy(f => f.Category).OrderBy(g => g.Key);

            foreach (var group in groupedFindings)
            {
                writer.WriteLine($"## {group.Key} Patches Detected");
                writer.WriteLine();
                writer.WriteLine("Module\tFunction\tPatch Type\tAddress\tOffset\tPattern");

                foreach (var finding in group.OrderBy(f => f.Address))
                {
                    string moduleName = Path.GetFileName(finding.ModuleName);
                    string funcName = finding.FunctionName ?? "unknown";
                    writer.WriteLine($"{moduleName}\t{funcName}\t{finding.PatchType}\t0x{finding.Address:X16}\t0x{finding.Offset:X8}\t{finding.Pattern}");
                }

                writer.WriteLine();
                Console.WriteLine($"[!] WARNING: {group.Count()} {group.Key} patch(es) detected!");
            }
        }

        // -------------------------- DUMP MODULES ----------------------------

        private static void DumpModules(DataTarget dataTarget, ClrRuntime runtime, string assembliesFolder, bool dumpAllNonMicrosoft)
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
                        DumpModule(dataTarget, module, assembliesFolder);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"[!] Failed to dump module {assemblyName ?? moduleName}: {ex.Message}");
                    }
                }
            }
        }

        private static void DumpModule(DataTarget dataTarget, ClrModule module, string assembliesFolder)
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
            string extension = DeterminePeExtension(buffer, filePathFromModule);

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

            string fullPath = Path.Combine(assembliesFolder, fileName);
            File.WriteAllBytes(fullPath, buffer);

            Console.WriteLine($"[+] Dumped assembly: {fileName}");
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
    }
}
