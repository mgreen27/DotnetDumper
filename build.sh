#!/bin/bash
set -euo pipefail

echo "[+] Building DotnetDumper for Windows x64, x86 and ARM64..."

# Clean previous builds
rm -rf bin/ obj/

# Build for Windows x64
echo -e "\n[+] Building x64..."
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./bin/ -p:AssemblyName=DotnetDumper "-p:NoWarn=IL2026%3BIL2104"
ls -lh bin/DotnetDumper.exe
shasum -a 256 bin/DotnetDumper.exe

# Build for Windows x86
echo -e "\n[+] Building x86..."
dotnet publish -c Release -r win-x86 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./bin/ -p:AssemblyName=DotnetDumper_x86 "-p:NoWarn=IL2026%3BIL2104"
ls -lh bin/DotnetDumper_x86.exe
shasum -a 256 bin/DotnetDumper_x86.exe

# Build for Windows ARM64
echo -e "\n[+] Building ARM64..."
dotnet publish -c Release -r win-arm64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./bin/ -p:AssemblyName=DotnetDumper_arm64 "-p:NoWarn=IL2026%3BIL2104"
ls -lh bin/DotnetDumper_arm64.exe
shasum -a 256 bin/DotnetDumper_arm64.exe

# Clean up build artifacts
rm -rf obj/ bin/Release/ bin/DotnetDumper*.pdb

echo -e "\n[+] Build complete:"