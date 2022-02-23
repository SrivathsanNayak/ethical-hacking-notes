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
