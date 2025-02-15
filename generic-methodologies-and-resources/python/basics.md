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
• 0
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