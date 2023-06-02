# Python 201

1. [Decorators](#decorators)
2. [Generators](#generators)
3. [Serialization](#serialization)
4. [Closures](#closures)

## Decorators

* Decorators - used to wrap another function to extend behavior of wrapped function without modifying it.

```py
from datetime import datetime
import time

def logger(func):
  def wrapper():
    print("-"*50)
    print("Execution started at {}".format(datetime.today().strftime("%H:%M:%S")))
    # print timestamp before function is called

    func()
    
    print("Execution completed at {}".format(datetime.today().strftime("%H:%M:%S")))
    print("-"*50)
    # print timestamp after function is called
  return wrapper

# name of decorator function should be placed with @ symbol
# directly above function to be wrapped

@logger
def demo_function():
  print("Executing a task")
  time.sleep(3)
  print("Task completed")

demo_function()

# first, the timestamp is printed
# then the message from demo_function() is printed
# after 3 seconds, the message followed by timestamp is printed

# instead of using the @ symbol
# we can also directly call it using
# logger(demo_function())
```

* We can also pass arguments to decorators.

```py
from datetime import datetime
import time

def logger_args(func):
  def wrapper(*args, **kwargs):
    print("-"*50)
    print("Execution started at {}".format(datetime.today().strftime("%H:%M:%S")))

    func(*args, **kwargs)
    # pass the arguments to the wrapped function
    
    print("Execution completed at {}".format(datetime.today().strftime("%H:%M:%S")))
    print("-"*50)
  return wrapper

@logger_args
def demo_function_args(sleep_time):
  print("Executing task")
  time.sleep(sleep_time)
  print("Completed task")

demo_function_args(1)
demo_function_args(2)
demo_function_args(3)
# all functions are executed
```

## Generators

* Generator - function that returns an iterator using the keyword ```yield``` instead of ```return```.

* While ```return``` exits the function, ```yield``` pauses the function and saves the state of variables.

* When the generator function is called, it does not execute the function body immediately; it returns a generator object that can be iterated over to produce the values.

```py
def gen_demo():
  n = 1
  yield n

  n += 1
  yield n

  n += 1
  yield n

test = gen_demo()
print(test)
# prints generator object address

print(next(test))
# 1
# prints the next item from the iterator

print(next(test))
# 2

print(next(test))
# 3

# if we call the next() function once more
# we get a StopIteration error

test2 = gen_demo()
for a in test2:
  print(a)
  # 1
  # 2
  # 3

```

* We can also create generator functions with loops.

```py
def xor_static_key(a):
  key = 0x5
  for i in a:
    yield chr(ord(i) ^ key)

for i in xor_static_key("test")
  print(i)
  # prints test XOR with 0x5 key
```

* Similar to lambda functions, anonymous generators are supported.

```py
xor_static_key_demo = (chr(ord(i) ^ 0x5) for i in "test")
# parentheses instead of square brackets

print(xor_static_key_demo)
# prints generator object

for i in xor_static_key_demo:
  print(i)
  # iterate through iterator
```

## Serialization

* Data serialization is the process of converting structured data to a format that allows storage of data.

* Serialization can be reversed to recover its original structure; it's called deserialization.

```py
import pickle
# library for serialization as example

things = {"apple": 1, "banana": 20, "carrot": 50}

serialized = pickle.dumps(things)
print(serialized)
# prints serialized data, in binary

things_v2 = pickle.loads(serialized)
print(things_v2)
# prints deserialized data
# the original dictionary

# we can save the serialized version to a file
# wb refers to write binary
with open("things.pickle", "wb") as handle:
  pickle.dump(things, handle)

# to load the serialized file by deserializing
with open("things.pickle", "rb") as handle:
  things_v3 = pickle.load(handle)

print(things_v3)
# prints the same dictionary
```

## Closures

* Closure - nested function that allows to access variables of outer function, even after outer function is closed.

* Usually, in nested functions, the inner function has access to variables defined in the outer function.

```py
def print_out(a):
  print("Outer: {}".format(a))

  def print_in():
    print("\tInner: {}".format(a))
  
  print_in()

print_out("test")

# this prints both Outer and Inner message
# nested functions
```

```py
# using closures

def print_out(a):
  print("Outer: {}".format(a))

  def print_in():
    print("\tInner: {}".format(a))
  
  return print_in
  # here, we are not calling closure function (inner function) directly

test2 = print_out("test")

# if we call print_out("test")
# only Outer function message is printed

# even if we delete the function here, closure function will work
del print_out

test2()
# prints both Outer and Inner functions
# it remembers the value, even after executing and deleting the function
```
