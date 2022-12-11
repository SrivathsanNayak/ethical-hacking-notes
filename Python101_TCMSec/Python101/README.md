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
