# OOP

1. [Intro](#intro)
2. [Classes and Objects](#classes-and-objects)
3. [Inheritance](#inheritance)
4. [Encapsulation](#encapsulation)
5. [Polymorphism](#polymorphism)
6. [Operator Overloading](#operator-overloading)
7. [Class Decorators](#class-decorators)

## Intro

* Object Oriented Programming groups variables & methods.

* OOP structures software into reusable blueprints (classes), which can create objects.

* These classes contain data (attributes), and functions (methods) to modify the data.

* Advantages of OOP:

  * Model & group complex data in reusable way
  * Leverage existing structures (inheritance)
  * Enables class-specific behavior (polymorphism)
  * Secure & protect attributes & methods (encapsulation)
  * Extendible & modular (overloading)

## Classes and Objects

```py
class Person:
  'Person base class'
  # above line is a class documentation string 

  # class attribute
  # shared by all objects
  wants_to_hack = True

  # to define instance of object
  # method which takes self arg as reference to object
  # invoked automatically whenever object initiated

  def __init__(self, name, age):
    self.name = name
    self.age = age
  
  # user-defined method
  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.age))
  
  def birthday(self):
    self.age += 1

# create instance of class
bob = Person("bob", 30)
alice = Person("alice", 20)

print(bob)
print(alice)
# prints Person objects

print(bob.name)
print(alice.age)
# prints attribute values of objects

# we also have class-specific functions

print(hasattr(bob, "age"))
# checks if the object has the attribute mentioned
# this returns True

print(getattr(bob, "name"))
# returns attribute value for object

setattr(bob, "house", 2)
# set attribute for object, creates attribute if it does not exist

print(getattr(bob, "house"))

delattr(bob, "house")
# deletes attribute
# if we try to access it now, we get AttributeError

# we can use the user-defined methods

bob.print_name()
alice.print_age()
# each object calls the function with their own attributes

bob.age = 31
bob.print_age()
# 31

bob.birthday()
bob.print_age()
# 32

# check class attributes
print(Person.wants_to_hack)
print(alice.wants_to_hack)
# both print True

# changes made to class attributes change it for all objects
# but it is not true the other way around

# we have special built-in attributes for all classes
print(Person.__dict__)
# prints namespace dictionary

print(Person.__doc__)
# prints "Person base class", the class documentation string

# we can use del to delete the attributes, objects or classes

del bob.name
# bob.print_name() throws AttributeError

del Person
# delete the class
print(alice.name)
# this prints the name even though we have deleted the class
# but we cannot create a new object now
```

## Inheritance

* Inheritance is used to create a new class derived from a parent class by avoiding redundancy.

```py
# base or parent class
class Person:
  'Person base class'
  wants_to_hack = True

  def __init__(self, name, age):
    self.name = name
    self.age = age
  
  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.age))
  
  def birthday(self):
    self.age += 1

# derived or child class
class Hacker(Person):
  def __init__(self, name, age, cves):
    super().__init__(name, age)
    # super() refers to base class
    self.cves = cves
  
  def print_name(self):
    print("My name is {} and I have {} CVEs".format(self.name, self.cves))
  
  def total_cves(self):
    return self.cves

bob = Person("bob", 30)
alice = Hacker("alice", 20, 5)

bob.print_name()
alice.print_name()
# different outputs

bob.birthday()
alice.birthday()
# the child class has access to all attributes and methods of parent class
# but it is not true the other way around

bob.print_age()
# 31
alice.print_age()
# 21

print(alice.total_cves())
# 5
# print(bob.total_cves()) throws AttributeError

print(issubclass(Hacker, Person))
# True
print(issubclass(Person, Hacker))
# False

print(isinstance(bob, Person))
# True
print(isinstance(bob, Hacker))
# False
print(isinstance(alice, Person))
# True
print(isinstance(alice, Hacker))
# True
```

## Encapsulation

* Encapsulation - restricting access using OOP.

```py
class Person:
  'Person base class'
  wants_to_hack = True

  def __init__(self, name, age):
    self.name = name
    self.__age = age
    # underscores added to protect the variable

  # to interact with internalised variables in encapsulation
  # we can use getters and setters

  def get_age(self):
    return self.__age
  
  def set_age(self, age):
    self.__age = age

  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.__age))
  
  def birthday(self):
    self.__age += 1

bob = Person("bob", 30)
# print(bob.age) throws AttributeError
# print(bob.__age) too throws AttributeError

print(bob.get_age())
# 30
bob.set_age(31)
print(bob.get_age())
# 31
bob.birthday()
print(bob.get_age())
# 32

print(bob.__dict__)
# prints all attributes and values, including the private ones
# this shows that the private attribute is named as _Person__age
# so encapsulation is not reliable for security

bob._Person__age = 50
print(bob.get_age())
# 50
```

## Polymorphism

* Polymorphism - using a common interface multiple times, like using the same function with different types of arguments.

```py
class Person:
  'Person base class'
  wants_to_hack = True

  def __init__(self, name, age):
    self.name = name
    self.age = age
  
  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.age))
  
  def birthday(self):
    self.age += 1

class Hacker(Person):
  def __init__(self, name, age, cves):
    super().__init__(name, age)
    self.cves = cves
  
  def print_name(self):
    print("My name is {} and I have {} CVEs".format(self.name, self.cves))
  
  def total_cves(self):
    return self.cves

bob = Person("bob", 30)
alice = Hacker("alice", 25, 10)
people = [bob, alice]

for person in people:
  person.print_name()
  print(type(person))
# we are using the same function
# but it gives different outputs

def obj_dump(object):
  object.print_name()
  print(object.age)
  object.birthday()
  print(object.age)
  print(object.__class__.__name__)
# using the same function

obj_dump(bob)
obj_dump(alice)
```

## Operator Overloading

```py
class Person:
  'Person base class'
  wants_to_hack = True

  def __init__(self, name, age):
    self.name = name
    self.age = age
  
  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.age))
  
  def birthday(self):
    self.age += 1

  # inbuilt function for printing class object
  # inbuilt functions denoted by underscores before and after name
  def __str__(self):
    return "My name is {} and I am {} years old".format(self.name, self.age)
  
  # returns object that represents sum of two objects
  def __add__(self, other):
    # other refers to another instance of the class
    return self.age + other.age

bob = Person("bob", 30)
alice = Person("alice", 25)

print(bob)
# by default, this prints out the class object and its address in memory
# but due to __str__
# this prints the custom message

print(bob + alice)
print(alice + bob)
# both print 55

# we can implement multiple dunder methods
# using other operators
```

## Class Decorators

```py
class Person:
  'Person base class'
  wants_to_hack = True

  def __init__(self, name, age):
    self.name = name
    self.__age = age

  def get_age(self):
    return self.__age
  
  def set_age(self, age):
    self.__age = age

  # we can use property decorators
  # the method is called as a property
  @property
  def age(self):
    return self.__age

  # property functions can also include setters and deleters
  @age.setter
  def age(self, age):
    self.__age = age
  
  @age.deleter
  def age(self):
    del self.__age

  # we can use class method decorators
  # this bounds to the class, not the object
  @classmethod
  def wants_to(cls):
    return cls.wants_to_hack
  
  # class method decorator
  # to create instances of class
  @classmethod
  def bob_factory(cls):
    return cls("bob", 30)
  
  # static method decorators
  # allow us to define static methods
  # these methods cannot access class attributes and per-instance attributes
  # these methods do not take any parameters
  @staticmethod
  def static_print():
    print("Static message")

  def print_name(self):
    print("My name is {}".format(self.name))

  def print_age(self):
    print("My age is {}".format(self.__age))
  
  def birthday(self):
    self.__age += 1

bob = Person("bob", 30)
# by default, print(bob.age) throws Attribute Error
# after using property decorators, it would work

print(bob.age)
# 30

# after using property getters, setters and deleters
bob.age = 50
print(bob.age)
# 50

# del bob.age would delete the attribute

print(Person.wants_to())
# True

# use class method decorators to create more instances
bob1 = Person.bob_factory()
bob2 = Person.bob_factory()

bob1.print_name()
bob2.print_name()

# static methods can be called by the class as well as its instances
Person.static_print()
bob2.static_print()
# prints the same output
```
