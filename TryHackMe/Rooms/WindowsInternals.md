# Windows Internals - Medium

1. [Processes](#processes)
2. [Threads](#threads)
3. [Virtual Memory](#virtual-memory)
4. [Dynamic Link Libraries](#dynamic-link-libraries)
5. [Portable Executable Format](#portable-executable-format)
6. [Interacting with Windows Internals](#interacting-with-windows-internals)

## Processes

* Process - maintains execution of program; an app can contain multiple processes.

* Process components:

  * Private virtual address space
  * Executable program
  * Open handles
  * Security context
  * Process ID
  * Threads

* We can observe processes using utilities such as Process Explorer and Procmon.

```markdown
1. What is the process ID of "notepad.exe"? - 5984

2. What is the parent process ID of the previous process? - 3412

3. What is the integrity level of the process? - High
```

## Threads

* Thread - executable unit employed by process and scheduled based on device factors; controls the execution of a process.

* Thread components:

  * Stack
  * Thread local storage
  * Stack argument
  * Context structure

```markdown
1. What is the thread ID of the first thread created by notepad.exe? - 5908

2. What is the stack argument of the previous thread? - 6584
```

## Virtual Memory

* Virtual memory - allows other internal components to interact with memory as if it was physical memory without risk of collisions between apps; provides each process with a private virtual address space.

```markdown
1. What is the total theoretical maximum virtual address space of a 32-bit x86 system? - 4 GB

2. What default setting flag can be used to reallocate user process address space? - increaseUserVA

3. What is the base address of "notepad.exe"? - 0x7ff652ec0000
```

## Dynamic Link Libraries

* DLL - library that contains code & data that can be used by multiple programs simultaneously.

* DLLs can be loaded in a program using load-time dynamic linking or run-time dynamic linking.

* In malicious code, threat actors will often use run-time dynamic linking as the malicious program may need to transfer files between memory regions, and transferring a DLL is easier than importing using other file requirements.

```markdown
1. What is the base address of "ntdll.dll" loaded from "notepad.exe"? - 0x7ffd0be20000

2. What is the size of "ntdll.dll" loaded from "notepad.exe"? - 0x1ec000

3. How many DLLs were loaded by "notepad.exe"? - 51
```

## Portable Executable Format

* PE (Portable Executable) format defines info about executable and stored data; it also defines structure of how data components are stored.

* The PE and COFF (Common Object File Format) files make up the PE format.

* Components of structure of PE data:

  * DOS Header
  * DOS Stub
  * PE File Header
  * Image Optional Header
  * Data Dictionaries
  * Section Table

```markdown
1. What PE component prints the message "This program cannot be run in DOS mode"? - DOS Stub

2. What is the entry point reported by DiE? - 000000014001acd0

3. What is the value of "NumberOfSections"? - 0006

4. What is the virtual address of ".data"? - 00024000

5. What string is located at the offset "0001f99c"? - Microsoft.Notepad
```

## Interacting with Windows Internals

* Windows API provides native functionality to interact with Windows OS; the API contains Win32 API and Win64 API.

* By default, an app cannot interact with Windows kernel or modify physical hardware, and requires an interface; the switch between user mode and kernel mode is facilitated by system & API calls (switching point).

```markdown
1. Enter the flag obtained from the executable below. - THM{1Nj3c7_4lL_7H3_7h1NG2}
```
