# Abusing Windows Internals - Hard

1. [Abusing Processes](#abusing-processes)
2. [Expanding Process Abuse](#expanding-process-abuse)
3. [Abusing Process Components](#abusing-process-components)
4. [Abusing DLLs](#abusing-dlls)
5. [Memory Execution Alternatives](#memory-execution-alternatives)
6. [Case Study in Browser Injection and Hooking](#case-study-in-browser-injection-and-hooking)

## Abusing Processes

* Process injection - injecting malicious code into a process through legit functionality or components.

* Major types of process injection:

  * Process hollowing - inject code into a suspended and 'hollowed' target process.

  * Thread execution hijacking - inject code into a suspended target thread.

  * Dynamic-link library injection - inject a DLL into process memory.

  * Portable executable injection - self-inject a PE image pointing to a malicious function into a target process.

* Steps of shellcode injection (process injection):

  * Open a target process with all access rights
  * Allocate target process memory for the shellcode
  * Write shellcode to allocated memory in the target process
  * Execute shellcode using a remote thread

```shell
#in CLI
tasklist /v
#identify PID of any process running as THM-Attacker
#supply PID to execute given shellcode-injector.exe

.\shellcode-injector.exe 4036
#gives flag
```

```markdown
1. What flag is obtained after injecting the shellcode? - THM{1nj3c710n_15_fun!}
```

## Expanding Process Abuse

* Process hollowing is similar to shellcode injection as it allows to inject an entire malicious file into a process; by un-mapping the process and injecting specific PE data & sections.

```markdown
1. What flag is obtained after hollowing and injecting the shellcode? - THM{7h3r35_n07h1n6_h3r3}
```

## Abusing Process Components

```markdown
1. What flag is obtained after hijacking the thread? - THM{w34p0n1z3d_53w1n6}
```

## Abusing DLLs

```shell
#in cmd
#give name of process with DLL as argument
.\dll-injector.exe RuntimeBroker.exe .\evil.dll
```

```markdown
1. What flag is obtained after injecting the DLL? - THM{n07_4_m4l1c10u5_dll}
```

## Memory Execution Alternatives

* Invoking function pointers

* Asynchronous procedure calls

* Section manipulation

```markdown
1. What protocol is used to execute asynchronously in the context of a thread? - Asynchronous Procedure Calls

2. What is the Windows API call used to queue an APC function? - QueueUserAPC

3. Can the void function pointer be used on a remote process? - n
```

## Case Study in Browser Injection and Hooking

* Browser hooking allows malware (Trickbot) to hook certain API calls that can be used to intercept credentials.

* For Trickbot, the hooking function injects itself into browser processes using reflective injection and hook API calls from the injected function.

```markdown
1. What alternative Windows API call was used by TrickBot to create a new user thread? - RtlCreateUserThread

2. Was the injection techniques employed by TrickBot reflective? - y

3. What function name was used to manually write hooks? - write_hook_iter
```
