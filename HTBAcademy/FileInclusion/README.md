# File Inclusion

1. [Intro to File Inclusions](#intro-to-file-inclusions)

## Intro to File Inclusions

* If functionalities such as ```HTTP parameters``` are not securely coded, an attacker can manipulate them to display contents of local files on the hosting server, leading to a ```LFI (Local File Inclusion)``` vulnerability.

* ```LFI``` vulnerabilities can lead to source code disclosure, sensitive data exposure and even remote code execution.

* These vulnerabilities can occur in popular web servers & development frameworks such as ```PHP```, ```NodeJS```, ```Java``` and ```.Net```.

* List of functions which may read content and/or execute files:

| **Function**             | **Read Content** | **Execute** | **Remote URL** |
|--------------------------|------------------|-------------|----------------|
| **_PHP_**                |                  |             |                |
| include()/include_once() | Yes              | Yes         | Yes            |
| require()/require_once() | Yes              | Yes         | No             |
| file_get_contents()      | Yes              | No          | Yes            |
| fopen()/file()           | Yes              | No          | No             |
| **_NodeJS_**             |                  |             |                |
| fs.readFile()            | Yes              | No          | No             |
| fs.sendFile()            | Yes              | No          | No             |
| res.render()             | Yes              | Yes         | No             |
| **_Java_**               |                  |             |                |
| include                  | Yes              | No          | No             |
| import                   | Yes              | Yes         | Yes            |
| **_.NET_**               |                  |             |                |
| @Html.Partial()          | Yes              | No          | No             |
| @Html.RemotePartial()    | Yes              | No          | Yes            |
| Response.WriteFile()     | Yes              | No          | No             |
| include                  | Yes              | Yes         | Yes            |
