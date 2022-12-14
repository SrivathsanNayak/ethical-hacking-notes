# Python 101

1. [Intro](#intro)
2. [Basics](#basics)

## Intro

* Python2 is EOL; Python3 stores strings as unicode by default (not ascii).

* In Python, indentation is used to indicate code blocks.

* Backslashes "\" can be used to interpret multiple lines as a single line.

## Basics

* Variables & data types:

```python
name = "neut"
name_length = 4

print(type(name))
#str

print(type(name_length))
#int

name_len = int("4")
print(type(name_len))
#int

name_list = ["a", "b", "c"]
name1, name2, name3 = name_list
print(name1, name2, name3)
#a b c

#there are other data types as well
```

* Numbers:

```python
t1_int = 1

t1_float = 1.0

t1_complex = 3.14j

t1_hex = 0xa
print(t1_hex)
#10
print(type(t1_hex))
#int

t1_octal = 0o10
print(t1_octal)
#8
print(type(t1_octal))
#int

print(1 + 0x1 + 0o1)
#3

#helper functions

print(abs(4), abs(-4))
#4 4

print(round(8.4), round(8.5), round(8.6))
#8 8 9

print(bin(8), hex(8))
#0b1000 0x8
```

* Strings:

```python
string1 = "A String!"

string2 = """multi-line
quote
!"""

#escaped characters
string3 = "I\"m an escaped character\nNewline"

string4 = "a" * 10
print(len(string4))
#10

#we can use inbuilt functions for strings

#functions can be chained as well

#string concatenation
print("String4 is " + str(len(string4)) + "characters long!")

#using format placeholder
print("String4 is {} characters long!".format(len(string4)))
```

* Booleans & Operators:

```python
not_valid = False

print(not_valid == True)
#False

print(not_valid != True)
#True

print(not not_valid)
#True

print((10 < 9) == True)
#False

print(10 < 9)
#False

print(bool(0))
#False

print(bool(1))
#True

x = 13
y = 5

print(bin(x))
#0b1101

print(bin(x)[2:].rjust(4,"0"))
#1101
#remove 0b from binary
#and ensure 4-digit output, with 0s to fill in

print(x & y)
#bitwise operator AND
```

* Tuples:

```python
#immutable
items = ("item1", "item2", "item3")

repeated = ("again",) * 4

mixed = ("A", 1, ("B", 0))

combined = items + repeated
#combine tuples

print("item2" in items)
#True

print(items.index("item3"))
#2

print(items[0])
#item1

#slicing
print(items[0:2])
#('item1', 'item2')
```

* Lists:

```python
#lists can be edited
list1 = ["A", "B", 1, 2.0, ["P"], [], list(), ("A")]
#can contain multiple types

print(list1[0])
#A

print(list1[4][0])
#P

list1[0] = "a"
print(list1)
#prints updated list

del list1[0]
#deletes first element

list1.insert(0, "A")
#inserts element at 0th index

list1.append("last")

#list has multiple inbuilt functions
#such as max, min, index, count, pop, extend

list2 = list1
#both lists point to same data
#if we make changes in list1, list2 will also change

#to only copy values
list3 = list1.copy()

list4 = ["1", "2", "3"]
list5 = list(map(float, list4))
#converts string to float
```

* Dictionaries:

```python
dict1 = {"a":1, "b":2, "c":3}
#key-value structure

print(len(dict1))
#3

print(dict1["a"])
#1

print(dict1.get("a"))
#1

print(dict1.keys())
#a,b,c

print(dict1.values())
#1,2,3

print(dict1.items())

#indices do not work in dictionaries
#duplicates not allowed in dicts

dict1["d"] = 4
print(dict1)
#modified

dict1["a"] = -1
#modified

dict1.update({"a":1})

#we can use pop() or del to remove pairs

dict1["c"] = {"a":1, "b":2}
#nested dictionaries

dict2 = {}
#empty dict
```

* Sets:

```python
#sets are unordered
#do not allow duplicates

set1 = {"a", "b", "c"}
print(set1)
#unordered output

set2 = {"a", "a", "a"}
print(set2)
#{'a'}
print(len(set2))
#1

set3 = set(("b", 1, False))

set1.add("d")
set3.update(set2)

list1 = ["a", "b", "c"]
set4 = {4, 5, 6}
set4.update(list1)
print(set4)
#contains 6 elements

#we can use union, intersection operations on sets
#we can use remove and discard on sets

#pop() removes arbitrary elements
```

* Conditionals:

```python
if True:
  print("true")
#gets printed

if False:
  print("false")
#does not get printed

if 1 < 1:
  print("1 < 1")
elif 1 <= 1:
  print("1 <= 1")
#only this gets printed
elif 2 <= 2:
  print("2 <= 2")
else:
  print("else code")

#comparisons can be combined using logical operators
```

* Loops:

```python
a = 1
while a < 5:
  a += 1
  print(a)


for i in [0,1,2,3,4]:
  print(i+6)

#nested for loops
for i in range(3):
  for j in range(3):
    print(i,j)

for i in range(5):
  if i == 2:
    break
    #ends loop
  print(i)

for i in range(5):
  if i == 2:
    continue
    #skip current iteration
  print(i)

for c in "string":
  print(c)

for k,v in {"a":1, "b":2, "c":3}.items():
  print(k,v)
```

* Reading & writing files:

```python
f = open('top-100.txt')
print(f.read())
#prints file content

arrayOfLines = f.readlines()
print(f.readlines())
#empty array because pointer is at EOF

f.seek(0)
print(f.readlines())
#prints all lines array

f.seek(0)
for line in f:
  print(line.strip())
f.close()

f = open("test.txt", "w")
#write mode
f.write("test line!")
f.close()
#"a" for append mode

#for larger files
with open('rockyou.txt', encoding='latin-1') as f:
  for line in f:
    pass
```

* User input:

```python
test = input()
print(test)
#prints input only after user enters some input

n = input("Enter a number:")
print(n)

while True:
  test = input("Enter IP: ")
  print(">>> {}".format(test))
  if test == "exit":
    break
  else:
    print("checking..")
```

* Exceptions & error handling:

```python
try:
  f = open("doesnotexistfilename")
except:
  print("File does not exist")
  #prints custom error

try:
  f = open("randomfile")
except FileNotFoundError:
  print("File does not exist")
except Exception as e:
  print(e)
  #prints specific error
finally:
  print("This always get printed")

n = 100
if n == 0:
  raise Exception("n cannot be 0")
if type(n) is not int:
  raise Exception("n must be an integer")
print(1/n)

#assertions
n = 1
assert(n != 0)
#triggers AssertionError if n is 0
print(1/n)
```

* Comprehensions:

```python
list1 = ['a', 'b', 'c']

#list comprehension
list2 = [x for x in list1]

list3 = [x for x in list1 if x == 'a']

list4 = [x for x in range(5)]

list5 = [hex(x) for x in range(5)]

list6 = [hex(x) if x > 0 else "X" for x in range(5)]

list7 = [x for x in range(5) if x == 0 or x == 1]

list8 = [[1,2,3],[4,5,6],[7,8,9]]

list9 = [y for x in list8 for y in x]
#[1,2,3,4,5,6,7,8,9]

set1 = {x + x for x in range(5)}
#{0,2,4,6,8}

list10 = [c for c in "stringtext"]

texthere = "".join(list10)
```

* Functions & code reuse:

```python
#define function
def function1():
  print("function hello")

#call function
function1()

#returns a value
def function2():
  return "hello!"

func2 = function2()
print(func2)

#accepts parameters
def function3(s):
  print("\t{}".format(s))

function3("param")

def function4(s1, s2):
  print("{} {}".format(s1,s2))

function4("check","this")

#default val
def function5(s1 = "default"):
  print(s1)

#for any number of arguments
def function6(s1, *more):
  print("{} {}".format(s1, " ".join([s for s in more])))

function6("func6", "arg1", "arg2", "arg3")

#dictionary of arguments
def function7(**ks):
  for a in ks:
    print(a, ks[a])

function7(a="1", b="2", c="3")

#global scope and function scope differ

v = 100

def function8():
  #specify global scoped variable
  global v
  v += 1
  print(v)

function8()
#101
print(v)
#101

#functions can call other functions
def function9():
  function1()

#recursion
def function10(x):
  print(x)
  if x > 0:
    function10(x-1)

function10(5)
```

* Lambdas:

```python
#single line anonymous function

add4 = lambda x : x + 4
print(add4(10))

add = lambda x, y : x + y
print(add(10,4))

print((lambda x, y : x * y)(2,3))

is_even = lambda x : x % 2 == 0

blocks = lambda x, y : [x[i:i+y] for i in range(0, len(x), y)]
print(blocks("string", 2))
#['st', 'ri', 'ng']

to_ord = lambda x : [ord(i) for i in x]
print(to_ord("ABCD"))
```
