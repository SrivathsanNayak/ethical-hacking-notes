# Flag Command - Very Easy

* checking the given Docker instance, we have a webpage which is serving a text-based adventure game

* by typing 'start', we can start the game - we can also check the source code for the page

* there are a few JS files containing the logic of the game - mainly 'commands.js' and 'main.js'

* checking 'main.js', it refers a few API endpoints - '/api/monitor' and '/api/options'

* '/api/options' endpoint includes a list of all possible commands, and we have a command value "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack" mapped to the key 'secret'

* after starting the game, if we enter this string as a command, we get the secret flag
