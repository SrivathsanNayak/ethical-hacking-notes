# Windows API

1. [C Data Types and Structures](#c-data-types-and-structures)
1. [Interfacing with Windows API](#interfacing-with-windows-api)
1. [Undocumented API Calls](#undocumented-api-calls)
1. [Direct Syscalls](#direct-syscalls)
1. [Execution from DLL](#execution-from-dll)

## C Data Types and Structures

* In C, we have some data types & structures which are not in Python:

  * Pointers - variables that store memory addresses, not values
  * Structures (struct) - collections of grouped variables under a single type

```py
from ctypes import *
# module which provides C-compatible data types
# used to directly call functions in DLLs from Python

# in C, data types need to be declared
b0 = c_bool(0)
b1 = c_bool(1)

print(b0)
# c_bool(False)
print(b0.value)
# False
print(b1)
# c_bool(True)
print(b1.value)
# True

# strings
c0 = c_char_p(b"test")
print(c0.value)
# b'test'

# when changing the value of pointer instances
# we are actually changing the memory location the variable is pointing to

print(c0)
# prints memory location
c0 = c_char_p(b"test1")
print(c0)
# different memory location
print(c0.value)
# b'test1'

# we can work with string buffers if address needs to be unchanged
p0 = create_string_buffer(5)
# 5 bytes buffer, initialized with null bytes
print(p0)
# prints memory location
print(p0.raw)
# b'\x00\x00\x00\x00\x00'
print(p0.value)
# b''

p0.value = b"a"
print(p0.raw)
# b'a\x00\x00\x00\x00'
print(p0)
# unchanged memory location

i = c_int(42)
pi = pointer(i)
# create pointer

print(i)
# c_long(42)
print(pi)
# prints address
print(pi.contents)
# c_long(42)

# we can also create a reference to a value
# using the byref() function
# and look at the value pointed to using cast()
pt = byref(p0)
print(pt)
# prints address
print(cast(pt, c_char_p).value)
# b'a'
print(cast(pt, POINTER(c_int)).contents)
# c_long(97)
# view integer representation
```

```py
from ctypes import *

# structures in C
class PERSON(Structure):
  _fields_ = [("name", c_char_p),
              ("age", c_int)]

bob = PERSON(b"bob", 30)
print(bob.name)
# b'bob'
print(bob.age)
# 30

person_array_t = PERSON * 3
# creating list for 3 people
print(person_array_t)

person_array = person_array_t()
# creating the actual array of the defined type

person_array[0] = PERSON(b"bob", 30)
person_array[1] = PERSON(b"alice", 20)
person_array[2] = PERSON(b"mallory", 50)

for person in person_array:
  print(person)
  print(person.name)
  print(person.age)
```

## Interfacing with Windows API

```py
from ctypes import *
from ctypes.wintypes import HWND, LPCSTR, UINT, INT, LPSTR, LPDWORD, DWORD, HANDLE, BOOL

# for a MessageBox hello-world implementation
# refer Microsoft Win32 API docs
# MessageBox in user32.dll
MessageBoxA = windll.user32.MessageBoxA
MessageBoxA.argtypes = (HWND, LPCSTR, LPCSTR, UINT)
MessageBoxA.restype = INT

print(MessageBoxA)
# function pointer

# parameter values
lpText = LPCSTR(b"World")
lpCaption = LPCSTR(b"Hello")
MB_OK = 0x00000000

# calls the MessageBoxA function
MessageBoxA(None, lpText, lpCaption, MB_OK)

# retrieves name of user for current thread
GetUserNameA = windll.advapi32.GetUserNameA
GetUserNameA.argtypes = (LPSTR, LPDWORD)
GetUserNameA.restype = INT

# to store username
buffer_size = DWORD(8)
# create buffer
buffer = create_string_buffer(buffer_size.value)

GetUserNameA(buffer, byref(buffer_size))
print(buffer.value)
# b'sv'

# for debugging, we can use GetLastError to get last error code
error = GetLastError()

if error:
  print(error)
  print(WinError(error))

# using Windows-specific structures
class RECT(Structure):
  _fields_ = [("left", c_long),
              ("top", c_long),
              ("right", c_long),
              ("bottom", c_long)]

# for GetWindowRect function
rect = RECT()

GetWindowRect = windll.user32.GetWindowRect
GetWindowRect.argtypes = (HANDLE, POINTER(RECT))
GetWindowRect.restype = BOOL

# to fetch handle, we can use GetForegroundWindow

hwnd = windll.user32.GetForegroundWindow()
GetWindowRect(hwnd, byref(rect))

print(rect.left)
print(rect.top)
print(rect.right)
print(rect.bottom)
```

## Undocumented API Calls

* Not all Windows APIs are documented on MSDN - most of the documented APIs operate in user mode.

* When calling a user mode API, we eventually end up in kernel mode as Windows API are an abstraction layer over the native API.

* The native API calls are defined in NTDLL; can be used for creating exploits as these are lesser used.

* Implementing ```VirtualAlloc``` using Windows API (MSDN):

```py
from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
# for Windows and C types
SIZE_T = c_size_t

VirtualAlloc = kernel32.VirtualAlloc
VirtualAlloc.argtypes = (wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAlloc.restype = wintypes.LPVOID

# values for constants from MSDN
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

ptr = VirtualAlloc(None, 1024 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
error = GetLastError()

if error:
  print(error)
  print(WinError(error))

# check where memory is allocated
print("VirtualAlloc: ", hex(ptr))

# to keep the Python process alive
# can verify alloc using ProcessHacker
input()
```

* Implementing ```VirtualAlloc``` using native API (NTDLL):

```py
from ctypes import *
from ctypes import wintypes

nt = windll.ntdll
NTSTATUS = wintypes.DWORD

NtAllocateVirtualMemory = nt.NtAllocateVirtualMemory
NtAllocateVirtualMemory.argtypes = (wintypes.HANDLE, POINTER(wintypes.LPVOID), wintypes.ULONG, POINTER(wintypes.ULONG), wintypes.ULONG, wintypes.ULONG)
NtAllocateVirtualMemory.restype = NTSTATUS

# GetCurrentProcess to get pseudo handle for current process
# pseudo handle defined as a constant
handle = 0xffffffffffffffff
base_address = wintypes.LPVOID(0x0)
zero_bits = wintypes.ULONG(0)
size = wintypes.ULONG(1024 * 12)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

ptr = NtAllocateVirtualMemory(handle, byref(base_address), zero_bits, byref(size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

if ptr != 0:
  print("error")
  print(ptr)

print("NtAllocateVirtualMemory: ", hex(base_address.value))

input()
```

## Direct Syscalls

* Every native API call has a specific number that represents it (syscall), these differ between different versions of Windows.

* To make a syscall, we need to move the correct number to a register; in x64, the syscall instruction will then enter kernel mode.

* With direct syscalls in Assembly, we can completely remove any Windows DLL imports:

```py
from ctypes import *
from ctypes import wintypes

SIZE_T = c_size_t
NTSTATUS = wintypes.DWORD

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# syscalls referred from online sources like
# Windows system call tables

# for Windows 10, 20H2 version
# syscall number for NtAllocateVirtualMemory is 0x0018

# to check if syscall succeeded or not
def verify(x):
  if not x:
    raise WinError()

# we can use an app like x64dbg to write Assembly code
# it has to be stored as shellcode in Python for it to work

"""
mov r10, rcx
mov eax, 0x18
syscall
ret
"""

# shellcode
buf = create_string_buffer(b"insert shellcode from x64dbg")
buf_addr = addressof(buf)
print(hex(buf_addr))

# we also need to change memory protection to allow execute operation
# for the shellcode to work

VirtualProtect = windll.kernel32.VirtualProtect
VirtualProtect.argtypes = (wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtect.restype = wintypes.INT

old_protection = wintypes.DWORD(0)
protect = VirtualProtect(buf_addr, len(buf), PAGE_EXECUTE_READWRITE, byref(old_protection))
verify(protect)

syscall_type = CFUNCTYPE(NTSTATUS, wintypes.HANDLE, POINTER(wintypes.LPVOID), wintypes.ULONG, POINTER(wintypes.ULONG), wintypes.ULONG, wintypes.ULONG)
syscall_function = syscall_type(buf_addr)

# to make the actual syscall

handle = 0xffffffffffffffff
base_address = wintypes.LPVOID(0x0)
zero_bits = wintypes.ULONG(0)
size = wintypes.ULONG(1024 * 12)

ptr = syscall_function(handle, byref(base_address), zero_bits, byref(size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)

if ptr != 0:
  print("error")
  print(ptr)

print("Syscall allocation: ", hex(base_address.value))

input()
```

## Execution from DLL

* DLLs (Dynamic Link Libraries) are similar to executables; these files contain code & data that can be used by multiple programs.

* DLLs cannot be directly executed, but they can be linked or loaded at run time.

* Custom DLL used for this example (can be compiled in Visual Studio):

```c
#include "pch.h"
#include <stdio.h>

extern "C"
{
  __declspec(dllexport) void hello()
  {
    puts("hello from dll");
  }
  __declspec(dllexport) int length(char* input)
  {
    return strlen(input);
  }
  __declspec(dllexport) int add(int a, int b)
  {
    return a + b;
  }
  __declspec(dllexport) void add_p(int* a, int* b, int* result)
  {
    *result = *a + *b;
  }
};
```

* Using an app like ```Dependency Walker```, we can check the dependencies for our custom DLL.

* Execution from DLL:

```py
from ctypes import *

lib = WinDLL("<path to Dll.dll>")
lib.hello()
# prints hello message

# follow good practice of defining functions
lib.length.argtypes = (c_char_p, )
lib.length.restype = c_int
str1 = c_char_p(b"test")
print(lib.length(str1))
# 4

lib.add.argtypes = (c_int, c_int)
lib.add.restype = c_int
print(lib.add(2, 3))
# 5

lib.add_p.argtypes = (POINTER(c_int), POINTER(c_int), POINTER(c_int))
x = c_int(2)
y = c_int(4)
result = c_int(0)

print("Before addition ", result.value)
lib.add_p(byref(x), byref(y), byref(result))
print("After addition ", result.value)
```
