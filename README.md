# DotnetDumper
A tool to quickly dump reflected assemblies from process dumps for further analysis.


Usage:   
  DotnetDumper <dumpPath> [outputFolder] [--dump-all] [--json] [--encode [key]]   
  DotnetDumper --pid <pid> [outputFolder] [--dump-all] [--json] [--encode [key]]   

Examples:   
  DotnetDumper C:\dumps\w3wp.dmp   
  DotnetDumper C:\dumps\w3wp.dmp C:\analysis\w3wp   
  DotnetDumper C:\dumps\w3wp.dmp --dump-all   
  DotnetDumper --pid 4242 C:\analysis\w3wp --dump-all --json   
