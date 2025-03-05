## variables
```python
x = 10
y = "hey"

# number Operator  
# = Assignment
# + Addition
# - Subtraction
# * Multiplication
# / Division (results in float)
# // Division (results in truncation)
# ** Exponentiation
# % Modulus
# += 1  This assigns to y the previous y value plus 1.
x = 10 
y = 5 
print(x + y)
y += 1 # add 1 to y

# strings operator (in , " + ,*" )
# \n indicates a new line
# \t indicates a tab
x.strip() # removes any whitespace characters, including `"\n"`, `"\t"`, and spaces

x = "0xmid00"
x + ", leet hacker" # Assigns a new value to x.
x += "!!" # same as before it add !! to the x 
"mid" in x # return true 
x.upper() # 0XMID00 , but x still 0xmid00

x = "Hello Wolrd" 
print(x[0]) # H 
print(x[1]) # e
print(x[-1]) # d
print(x[0:3]) # Hel , From element 0 to element 3
print(x[4:0]) # lo Wolrd , From element 4 to the end
print(x[:])  # Hello Wolrd , From the beginning of the string to the end of the string
```

## input & output 
```python
name = "ahmed"
print(name) # output 

username = input("what is your usernmae ? ") 
age =  int(input("what is your age ? ")) # store aan integer in input 
print("username is", username, "and age is", age)
```

## controls flow
control the program execution and flow, such as conditional and loop ..
### condition 
```python
# Boolean values
• 0 # false
• 1 # true 
• False
• None
• “” - Empty string
• [ ] - Empty list (we will see them later)
Everything else is considered as True

# Operator
# logical operators that return True or False
< # Less than
<= # Less than or equal
== # Equal
> # Greater than
>= # Greater than or equal
!= # Not equal
is / is not # Object identity / negate
in / not in # Is inside / negate
And # Logical AND
Or # Logical OR
Not # Logical NOT

#  if-else statement
if expression:
  statement
else:
  statement
# example
number =  int(input("entre your age: "))
if number > 18:
  check_age = True
else:
  print("sorry your too youg")  

# nested if
if expression_1:
statement_1
if expression_2:
statement_2
if expression_3:
statement_3
else:
else_statement_of_first_if

# elif  
# If we want to evaluate several expressions we can se the if-elif-else statements:
if expression_1:
statement_1
elif expression_2:
statement_2
elif expression_3:
statement_3
else:
statement_4

#In Python, there is no switch / case statement!
```
### Loops
```python
# while
while condition:
  statements_block
post_while_statements

# example
x = 10
y = 1
while x > y:
  y += 1
print(y,x)  

# for 
for item in sequence:
  for_statements
post_for_statements

range(x,y) # sequence from x to y 
range(5) #  from 0 to 4.
range(5,10) # 5 .. 10
list(range(0,5)) # [0, 1, 2, 3, 4]
list(range(0,10,2)) # [0, 2, 4, 6, 8]

# example
x = 10
for i in range(x):
  print(i)
```
## Lists
```python
list = [1,2,“els”,4,5,‘something’,[0,9]] # The nested list ‘[6,7]’ is considered as a single element
simple_list = [1,2,3,4,5]

len(simple_list) # => 5 
simple_list[0] # => 1
simple_list[4] # => 5
simple_list[3:] # from inex 3 to the end so it '45'

simple_list[0] = "modifed!" # odife the element in the index 0
simple_list + ["new"] # add new element to the list
y = simple_list[2:4] # copy a part of list to y

simple_list.append("new") # appaend new element 

y = [7,8]
simple_list.append(y) # ,x,[a,b] . appaned a list as single element 
simple_list.extend(y) # ,x,a,b . appaned a list as separate elements
simple_list.insert(2,"new") # 1,2,"new",3,4 # add a new list element right before a specific index

del x[1] # delete element with index 1
del x[2:] # Delete all the elements with index greater than or equal to 2
x[1:2] [] # it delete the elements with index from 1 to 2 

x.remove(3) # find the element with the value 3 then delete it

# Method Description
list.pop(i) # Removes the item at the given position
list.sort() # Sorts a list ( they must be of the same type)
list.reverse() # Reverses the order of the elements in the list

```
## Dictionaries
```python
dictionary = {‘first’:‘one’, ‘second’:2} # “key:value”
x =  {"first":"one", "second":2, "thirth":"three"}
x["first"] #-> 'one'
len(x) #-> 3
x["second] += 1
x #-> {"first":"one", "second":3, "thirth":"threee"}

del x["first"] # delete " first’:‘one’ "
list(x.values()) #-> ["2", "three"]
list(x.keys()) #-> ["second", "three"]
list(x.items()) #-> [("secound", "3"), ("thirth", "three")]

"second" in x #-> True , check if itemes is existe
"three" in x.values() #-> True 
x.get("blabla", "sorry no found ") #-> check if the key exists and returns the associated value, otherwise print the message "sorry no found"

dummy_switch =  {
1: "you have choosen 1",
2: "you have choosen 2",
3: "you have choosen 3",
}
user = int(input("select an option (1/2/3)"))
if user in dummy_switch:
  print(dummy_switch[user])
else:
  print("wrong input")
```

## files 
```python

## 1. Open a File
f = open("file.txt", "r")  # Read mode
f = open("file.txt", "w")  # Write mode (overwrites file)
f = open("file.txt", "a")  # Append mode (adds to file)
f = open("file.txt", "rb") # Read binary mode

## 2. Read a File
content = f.read()         # Read full content
line = f.readline()        # Read one line
lines = f.readlines()      # Read all lines as a list
f.close()                 # Always close the file

## 3. Write to a File
f = open("file.txt", "w")
f.write("New content\n")  # Overwrites file
f.close()

## 4. Append to a File
f = open("file.txt", "a")
f.write("Appending data\n")  
f.close()

## 5. Using 'with' (Auto Close)
with open("file.txt", "r") as f:
    content = f.read()

## 6. Read File as Bytes (For Exploit Development)
with open("exploit.bin", "rb") as f:
    data = f.read()

## 7. Write Binary Data (Payloads)
with open("shellcode.bin", "wb") as f:
    f.write(b"\x90\x90\x90")  # Writing NOP sled

## 8. Check If File Exists
import os
if os.path.exists("file.txt"):
    print("File found!")

## 9. List Files in a Directory
import os
files = os.listdir("/tmp")  # List all files in /tmp

## 10. Read System Files (Linux PrivEsc)
with open("/etc/passwd", "r") as f:
    print(f.read())

# Notes:
# - Use 'rb' mode for binary payloads.
# - Use '/etc/passwd', '/etc/shadow', 'C:\\Windows\\System32\\drivers\\etc\\hosts' for info gathering.
# - Combine with os, subprocess for enumeration.
```

## Functions 
```python
def function_name(parameter1, parameter2,...):
  function_statements
  return expression
# example 
def sum(x,y):
  """ calcylat y +x """ #  definition in order to explain what that function does.
  return x + y
  
x = sum(5,5)  # to varible z 
print(x)
print("the sum is : ", sum(5,5)) # print the function value 
print("doc:",sum.__doc__) # call the function description

# asssign a function in dictionary
def a(x):
  print("the sum of",x,"and",x)
  return x + x
def b(x):
  print("the mul of", x,"and",x)
  return x * x

# Assign function a and b to dictionary values
function_switch = { 
1:a,
2:b,
}

user = int(input("entre an option 1(+)/2(*)"))
if user in function_switch:
  x = int(input("entre a number"))
  resulte = function_switch[user] (x) # call the right function using the dictionary (function_switch)
  print("the resultes is :", resulte)
else:
  print("wrong input !")

def func_test():
    return 10, 20  # This returns a tuple (10, 20)

a, b = func_test()

print(a)  # Output: 10
print(b)  # Output: 20

```

## Modules
```python
# my_double.py
""" my module """
some_value = "ahmed"
def double(x)
  """ double the input """
  return x * 2

****************************
# script.py
import my_module

print(my_module.some_value) #-> ahmed
print(my_module.double(5)) #-> 10
print(my_module.__doc__) #-> my module
****************************
# we had to write the module name each time we wanted to use an object. In order to directly use an object, we can use the following syntax:

# from module_name import object_name1, object_name2,...
from my_module import some_value
print(some_value) #-> ahmed

# from module_name import *
from my_module import *
print(some_value) #-> ahmed
```

## Classes 
```python
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

p1 = Person("Ahmed", 25)
print(p1.name, p1.age)  # Output: Ahmed 25
```
## scripting for pentesters
### Network sockets 
#### server
```python
import socket

srv_addr = input("entre the server ip addr: ")
srv_port = int(input("entre the  server port: "))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((srv_addr, srv_port))
s.listen(1)
print("listing ..")
connection, address =  s.accept()
print('Clinet connect with address ', address)
while 1:
  data = connection.recv(1024)
  if not data: break
  connection.sendall(b'--message reseived--\n')
  print(data.decode("utf-8"))
connection.close
```
#### client 
```python
import socket

srv = input("entre the srv ")
port = int(input("enter the port number"))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((srv, port))
print("connected") 
s.sendall(b'hello')
data = s.recv(1024)
if data:
  print("recv:",data.decode("utf-8"))
s.close 
```

#### examples scripts 

penetration testing notes in a structured, easy-to-read text format:

```python
┌───────────────────────────────────────────────────────┐
│                🛠 Python Libraries for Pentesting    │
└───────────────────────────────────────────────────────┘

📌 1. socket (Network Communication)
────────────────────────────────────────
- Used for scanning, creating connections, sending/receiving data.

🔹 Create a TCP socket:
  socket.socket(socket.AF_INET, socket.SOCK_STREAM)

🔹 Connect to a target:
  s.connect(("target.com", 80))

🔹 Send HTTP request:
  s.send(b"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")

🔹 Receive response:
  response = s.recv(1024).decode()

🔹 Bind & Listen (Simple Server):
  s.bind(("0.0.0.0", 4444))
  s.listen(5)
  conn, addr = s.accept()

✅ Used for port scanning, banner grabbing, reverse shell connections.

---------------------------------------------------------
📌 2. os (System Commands & File Interaction)
────────────────────────────────────────
- Interacts with the OS: executes commands, manipulates files.

🔹 Execute a system command:
  os.system("whoami")

🔹 Get current user & path:
  os.getlogin(), os.getcwd()

🔹 List files in a directory:
  os.listdir("/home/user")

🔹 Create, delete, rename files:
  os.mkdir("test"), os.rename("test", "new_test"), os.remove("file.txt")

🔹 Check if running as root:
  os.geteuid() == 0  → "Running as root!"

✅ Used for privilege checks, command execution, persistence.

---------------------------------------------------------
📌 3. platform (System Information)
────────────────────────────────────────
- Retrieves OS details, architecture, and hardware info.

🔹 Get OS information:
  platform.system(), platform.release(), platform.version()

🔹 Get CPU & architecture:
  platform.architecture(), platform.processor()

🔹 Get hostname & machine:
  platform.machine(), platform.node()

🔹 Get full system info:
  platform.uname()

✅ Used for target enumeration, identifying OS vulnerabilities.

---------------------------------------------------------
✅ Summary:
✔ socket    → Network tasks (scanning, shells)
✔ os        → System interaction (commands, files)
✔ platform  → System info (OS, CPU, architecture)
```


###### port scanner
```python
#!/bin/python
import socket

ip = input("entre the ip addr: ")
port_range = input("entre the ports rang, ex 10-50 :")

low_port = int(port_range.split("-") [0])
high_port = int(port_range.split("-") [1]) 

print ("\nscan from low_port:", low_port,"to high_port:", high_port) 

for port in range(low_port, high_port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    status = not (s.connect_ex((ip, port)))
    if status:
        print ("[+] PORT:", port,"OPEN")
    s.close
```

### HTTP Request
```python
# simple GET request

conn = http.client.HTTPSConnection("www.example.com")
conn.request("GET", "/")
response = conn.getresponse()
print(response.status, response.reason)
data = response.read()
print(data.decode())
conn.close()

+++++++++++++++++++++++++++++++++++++++++++++++++++++
# 
```