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

```markdown
1. What ETW component will build and configure sessions?

2. What event ID logs when a user account was deleted?
```

## Approaches to Log Evasion

```markdown
1. How many total events can be used to track event tampering?

2. What event ID logs when the log file was cleared?
```

## Tracing Instrumentation

## Reflection for Fun and Silence

```markdown
1. What reflection assembly is used?

2. What field is overwritten to disable ETW?
```

## Patching Tracing Functions

```markdown
1. What is the base address for the ETW security check before it is patched?

2. What is the non-delimited opcode used to patch ETW for x64 architecture?
```

## Providers via Policy

```markdown
1. How many total events are enabled through script block and module providers?

2. What event ID will log script block execution?
```

## Group Policy Takeover

```markdown
1. What event IDs can be disabled using this technique?

2. What provider setting controls 4104 events?
```

## Abusing Log Pipeline

```markdown
1. What type of logging will this method prevent?

2. What target module will disable logging for all Microsoft utility modules?
```

## Real World Scenario

```markdown
1. Enter the flag obtained from the desktop after executing the binary.
```
