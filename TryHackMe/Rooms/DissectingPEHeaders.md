# Dissecting PE Headers - Medium

1. [Overview of PE headers](#overview-of-pe-headers)
2. [IMAGE_DOS_HEADER and DOS_STUB](#image_dos_header-and-dos_stub)
3. [IMAGE_NT_HEADERS](#image_nt_headers)
4. [OPTIONAL_HEADER](#optional_header)
5. [IMAGE_SECTION_HEADER](#image_section_header)
6. [IMAGE_IMPORT_DESCRIPTOR](#image_import_descriptor)
7. [Packing and Identifying packed executables](#packing-and-identifying-packed-executables)

## Overview of PE headers

```markdown
1. What data type are the PE headers?
```

## IMAGE_DOS_HEADER and DOS_STUB

```markdown
1. How many bytes are present in the IMAGE_DOS_HEADER?

2. What does MZ stand for?

3. In what variable of the IMAGE_DOS_HEADER is the address of IMAGE_NT_HEADERS saved?

4. In the attached VM, open the PE file Desktop/Samples/zmsuz3pinwl in pe-tree. What is the address of IMAGE_NT_HEADERS for this PE file?
```

## IMAGE_NT_HEADERS

```markdown
1. In the attached VM, there is a file Desktop\Samples\zmsuz3pinwl. Open this file in pe-tree. Is this PE file compiled for a 32-bit machine or a 64-bit machine?

2. What is the TimeDateStamp of this file?
```

## OPTIONAL_HEADER

```markdown
1. Which variable from the OPTIONAL_HEADER indicates whether the file is a 32-bit or a 64-bit application?

2. What Magic value indicates that the file is a 64-bit application?

3. What is the subsystem of the file Desktop\Samples\zmsuz3pinwl?
```

## IMAGE_SECTION_HEADER

```markdown
1. How many sections does the file Desktop\Samples\zmsuz3pinwl have?

2. What are the characteristics of the .rsrc section of the file Desktop\Samples\zmsuz3pinwl
```

## IMAGE_IMPORT_DESCRIPTOR

```markdown
1. The PE file Desktop\Samples\redline imports the function CreateWindowExW. From which dll file does it import this function?
```

## Packing and Identifying packed executables

```markdown
1. Which of the files in the attached VM in the directory Desktop\Samples seems to be a packed executable?
```
