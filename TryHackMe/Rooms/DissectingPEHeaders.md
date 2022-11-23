# Dissecting PE Headers - Medium

1. [Overview of PE headers](#overview-of-pe-headers)
2. [IMAGE_DOS_HEADER and DOS_STUB](#image_dos_header-and-dos_stub)
3. [IMAGE_NT_HEADERS](#image_nt_headers)
4. [OPTIONAL_HEADER](#optional_header)
5. [IMAGE_SECTION_HEADER](#image_section_header)
6. [IMAGE_IMPORT_DESCRIPTOR](#image_import_descriptor)
7. [Packing and Identifying packed executables](#packing-and-identifying-packed-executables)

## Overview of PE headers

* A PE file is a COFF (Common Object File Format) data structure, and this format consists of PE files, DLLs, shared objects (in Linux) and ELF files.

* We can use tools such as ```wxHexEditor``` to view the Hex chars inside PE files.

* ```pe-tree``` can be used to analyze PE header.

```markdown
1. What data type are the PE headers? - STRUCT
```

## IMAGE_DOS_HEADER and DOS_STUB

* We can use ```wxHexEditor``` and ```pe-tree``` to analyze PE files.

* The ```IMAGE_DOS_HEADER``` consists of the first 64 bytes of the PE file.

* The first two bytes that say ```4D 5A``` translate to ```MZ``` in ASCII, and it is an identifier of the PE format.

* Some entries in ```IMAGE_DOS_HEADER```:

  * ```e_magic``` - has value of ```0x5a4d MZ```, which is using reverse byte order due to 'endianness'.

  * ```e_lfanew``` - has value of ```0x000000d8```, and denotes address from where IMAGE_NT_HEADERS start.

* The ```DOS_STUB``` entry includes section-specific info such as size, hashes and entropy; this code runs only if PE file is incompatible with the system being used to run it.

```markdown
1. How many bytes are present in the IMAGE_DOS_HEADER? - 64

2. What does MZ stand for? - Mark Zbikowski

3. In what variable of the IMAGE_DOS_HEADER is the address of IMAGE_NT_HEADERS saved? - e_lfanew

4. In the attached VM, open the PE file Desktop/Samples/zmsuz3pinwl in pe-tree. What is the address of IMAGE_NT_HEADERS for this PE file? - 0x000000f8
```

## IMAGE_NT_HEADERS

* [IMAGE_NT_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32) contains most of the vital info related to PE file.

* This header has the following contents:

  * NT_HEADERS
  * IMAGE_SECTION_HEADER
  * IMAGE_IMPORT_DESCRIPTOR
  * IMAGE_RESOURCE_DIRECTORY

* NT_HEADERS consists of the following:

  * Signature - first 4 bytes of NT_HEADERS

  * FILE_HEADER - includes multiple fields related to file such as number of sections and timestamp.

  * OPTIONAL_HEADER

```markdown
1. In the attached VM, there is a file Desktop\Samples\zmsuz3pinwl. Open this file in pe-tree. Is this PE file compiled for a 32-bit machine or a 64-bit machine? - 32-bit machine

2. What is the TimeDateStamp of this file? - 0x62289d45 Wed Mar  9 12:27:49 2022 UTC
```

## OPTIONAL_HEADER

* OPTIONAL_HEADER begins right after the end of the FILE_HEADER.

* Some of the important fields in OPTIONAL_HEADER are:

  * Magic - magic number tells whether PE file is 32-bit (0x010B) or 64-bit (0x020B).

  * AddressofEntryPoint - address from where Windows will begin execution, relative to ImageBase.

  * BaseOfCode and BaseOfData - addresses of code & data sections, relative to ImageBase.

  * ImageBase - preferred loading address of PE file in memory.

  * Subsystem - represents Subsystem required to run the image.

  * DataDirectory - structure containing import & export info of PE file.

```markdown
1. Which variable from the OPTIONAL_HEADER indicates whether the file is a 32-bit or a 64-bit application? - magic

2. What Magic value indicates that the file is a 64-bit application? - 0x020B

3. What is the subsystem of the file Desktop\Samples\zmsuz3pinwl? - 0x0003 WINDOWS_CUI
```

## IMAGE_SECTION_HEADER

* IMAGE_SECTION_HEADER includes info about different Sections; the common ones are:

  * ```.text``` - contains executable code for app

  * ```.data``` - contains initialized data of app
  
  * ```.rdata/.idata``` - contains import info of PE file

  * ```.ndata``` - contains uninitialized data

  * ```.reloc``` - contains relocation information of PE file

  * ```.rsrc``` - contains icons, images or other resources required for app UI

```markdown
1. How many sections does the file Desktop\Samples\zmsuz3pinwl have? - 7

2. What are the characteristics of the .rsrc section of the file Desktop\Samples\zmsuz3pinwl - 0xe0000040 INITIALIZED_DATA | EXECUTE | READ | WRITE
```

## IMAGE_IMPORT_DESCRIPTOR

* IMAGE_IMPORT_DESCRIPTOR structure contains info about different Windows APIs that the PE file loads when executed.

* By studying the import functions of a PE file, we can identify the activities that the PE file might perform.

```markdown
1. The PE file Desktop\Samples\redline imports the function CreateWindowExW. From which dll file does it import this function? - User32.dll
```

## Packing and Identifying packed executables

* Packers pack the PE file in a layer of obfuscation to avoid reverse-engineering and static analysis.

* ```pecheck``` is a tool used to analyze the PE file, similar to ```pe-tree```

* Indicators of a packed executable include:

  * Unconventional section names
  * High entropy values of sections
  * EXECUTE permissions for multiple sections
  * Significant difference between ```SizeOfRawData``` and ```Misc_VirtualSize```
  * Few import functions

```markdown
1. Which of the files in the attached VM in the directory Desktop\Samples seems to be a packed executable? - zmsuz3pinwl
```
