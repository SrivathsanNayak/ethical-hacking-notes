# Python Basics

* Programs in Python are saved with the .py extension, and have to start with a shebang:

```python
#!/bin/python3

print("Hello world!")
#prints string
print("""Multiple lines
        string""")
print("Concatenate " + "strings")

```

* The program can be run using ```python3 first.py``` or ```./first.py``` (has to be given executable permission first) in shell.

* Creating a program with the command ```vim programfile.py&``` allows us to modify the code and run the program in shell simultaneously.

* Variables and methods:

```python
#!/bin/python3

quote = "Be based, not cringe"
print(quote)
print(quote.upper()) #uppercase
print(quote.title()) #titlecase
print(len(quote)) #length

name = "Bruh"
age = 69
print("My name is " + name + " and I am " + str(age) + " years old.") #str(age) to convert int to string

age += 1
print(age)

```

* Functions:

```python
#!/bin/python3

name = "Bruh"
age = 25
gpa = 8.2

#example of function
def whoami():
    name = "Deez"
    age = 12
    print("My name is " + name + " and I am " + str(age) + " years old.")

whoami() #call the function

#parameters in function
def hundred(n):
    print(n+100)

hundred(15)

#many parameters
def add(x,y):
    print(x+y)

add(400,35)

#return value
def multiply(x,y):
    return x*y

print(multiply(3,2))

```

* Boolean expressions:

```python
#!/bin/python3

bool1 = True
bool2 = 3+3 == 9
bool3 = 3*3 == 9
bool4 = bool1 == bool2
bool5 = bool1 == bool3

print(bool1, bool2, bool3, bool4, bool5)
#True False True False True
```

* Conditional statements:

```python
#!/bin/python3

def drink(age,money):
    if (age >= 21) and (money >= 2):
        return "Purchased drink"
    elif (age >= 21) and (money < 2):
        return "Need more money"
    elif (age < 21) and (money >= 2):
        return "Too young"
    else:
        return "Young and poor"

print(drink(22,4))
print(drink(22,1))
print(drink(12,5))
print(drink(15,1))

```

* Lists:

```python
#!/bin/python3

players = ['Kohli', 'Dhoni', 'Gayle', 'Dhawan']

print(players[0]) #first item, index 0
print(players[1:3]) #from index 1, upto before index 3(excluding)
print(players[1:]) #from index 1 to end of list
print(players[:2]) #from start of list, upto index 2(excluding)
print(players[-1]) #last item, index -1

print(len(players)) #number of items in list                                                                                                                                                 
players.append('Sharma') #add item at end of list                                                                                                                                            
print(players)                                                                                                                                                                               
                                                                                                                                                                                             
players.pop()                                                                                                                                                                                
print(players) #remove item from end of list

players.pop(2) #remove item at index 2
print(players)
```

* Tuples:

```python
#!/bin/python3

grades = ('S', 'A', 'B', 'C', 'F')
#tuples are immutable
print(grades[1])

```

* Looping:

```python
#!/bin/python3

names = ['Sid', 'Joe', 'Ram', 'Kim']
for n in names:
    print(n)

i = 1
while (i < 5):
    print(i)
    i += 1
```

* Importing modules:

```python
#!/bin/python3

import sys #system function, parameters
from datetime import datetime as dt #import module as alias

print(sys.version)
print(dt.now())

```

* String functions:

```python
#!/bin/python3

snt = "This is a sample sentence."

snt_parts = snt.split() #splits string based on delimiter, space by default
snt_joined = ' '.join(snt_parts) #list of words are joined with delimiter separating words

print(snt_parts)
print(snt_joined)

quotes = "This contains \"quotes\"" #backslash used as escape character
print(quotes)

spaces = "  space   bar  "
print(spaces.strip()) #strips all space characters from string

print('A' in "Apple")
print("a" in 'Apple')
print("a".lower() in "Apple".lower())

fav = "Cake"
print("I like {}".format(fav)) #String format

```

* Dictionaries:

```python
#!/bin/python3

counts = {"A":10, "B":8, "C":9, "S":20} #key-value pairs
print(counts)

fruits = {"Best":["Mango", "Banana"], "OK":["Orange", "Apple"], "Bad":["Berries", "Pineapple"]}
print(fruits)

#add new key-value pair
fruits["Very bad"] = ["Tomato"]
print(fruits)

#another way to add pair
fruits.update({"Good": ["Jackfruit", "Grapes"]})
print(fruits)

#updating value
counts["C"] = 3
print(counts)

#returns value of key "C"
print(counts.get("C"))

```

* Sockets:

```python
#!/bin/python3

import socket
#sockets are used to connect to ports

HOST = '127.0.0.1' #localhost
PORT = 7777

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
#used to establish connection
#run command "nc -nvlp 7777" to initiate connection, this script will establish it

```

* Port Scanner script:

```python
#!/bin/python3

import sys
import socket
from datetime import datetime

#define target ip
if len(sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1]) #translate hostname to IPv4
else:
    print("Invalid input")
    print("Syntax: python3 scanner.py <ip>")

#banner
print("-" * 50)
print("Scanning target: " + target)
print("Time started: " + str(datetime.now()))
print("-" * 50)

#trying to connect to target
try:
    for port in range(1,500):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1) #socket timeout after 1 second to avoid infinite waiting time
        result = s.connect_ex((target, port)) #returns error indicator
        if result == 0:
            print("Port {} is open".format(port))
        s.close()

#exceptions in case of errors
except KeyboardInterrupt: #Ctrl+C, Ctrl+Z
    print("\nExiting program.")
    sys.exit() #exits program

except socket.gaierror:
    print("\nHostname could not be resolved.")                                                                                                                                               
    sys.exit()                                                                                                                                                                               
                                                                                                                                                                                             
except socket.error:                                                                                                                                                                         
    print("\nCould not connect to server.")                                                                                                                                                  
    sys.exit()

```
