#!/bin/bash
echo "[+] Building DotnetDumper for Windows x64..."

# Clean previous builds
rm -rf bin/ obj/

# Build for Windows x64
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./bin/

# Clean up build artifacts
rm -rf obj/ bin/Release/

echo "[+] Executable location: bin/DotnetDumper.exe"
ls -lh bin/DotnetDumper.exe
