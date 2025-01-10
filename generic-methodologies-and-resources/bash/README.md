# bash Basics 
## environment variables 
```bash
env #Checking Environment Variables
echo ${SHELL} # read the  individuale environment variable
```
## elements of the bash shell 
### shebang line 
```bash
`#! /bin/bash`
`#! /usr/bin/env bash` # help to find the location of the bash interpreter 
`#! /usr/bin/bash -x` # debugging, it print the commands + the argumeents
`#! /usr/bin/bash -r` # restricted bash shell
```
### debugging 
```bash
bash -n # check for syntax eroors before excuting 
bash -x # verbose mode

#if u want statrt debugging at given point in the script :
#! /bin/bash
set -x
# start debugging 
set +x 
# end debugging 
```

## Basics syntax
### variables 
```bash
# not that we can't leave a whitsspace  around the assignment symbole book = "test"
book="black hat bash" ; echo "the book name is ${book}" # or we can use ehco "...$book"
root_directory=$(ls -ld /) ; echo "${root_directory}" # assign the output of command to a variable
boo ="test" ; unset book ; echo "${book}" #=> null, unassign assigned variable 

#scoping variable 
# local varibale can be scoped using `local` keyword
#! /bin/env bash
PUBLISHER="0mid00"
print_name (){
local name
name="black hat bash"
echo " ${name} by ${PUBLISHER}"
}
print_name
echo "variable ${name} will not be printed becouse it is local variable"

```
### arithmetic operators 
```bash
let result="4 * 5" ;echo ${result} # using the `let` command 
result=((5 * 5)) ; echo ${result} # using double parentheses
result=$(expr 4 + 5) ; echo $(result) # using `expr` command
```
### arrays 
```bash
IP_ADDRESSES=(192.168.11.1 192.168.11.2 192.168.11.3) # assigan a array value
echo ${IP_ADDRESSES[*]} # print all the array values 
echo ${IP_ADDRESSES[1]} # print  a specific index of the array 
unset ${IP_ADDRESSES[0]} # deleting array elements
IP_ADDRESSES[1]="0.0.0.0" ; echo ${IP_ADDRESSES[1]} # swap array element 
```
### streams 
```bash
standard input (stdin)   | 0
standard output (stdout) | 1
standard error (stderr)  | 2
```
### redirection operators 
```bash
#stdout (> , >>)
echo "ahmed" > file.txt # redirect the standar output to the file file.txt
echo "ahmed" >> file.txt # append the stdout to the file file.txt
 
 #stderr (2>)
 ls -l / 2> file.txt 
 
# stdout + stderr (&>, >&)
ls -l / &> stdout_stderr.txt # redirect the both stdout and stderr to the file 
ls -l / 1> stdout.txt 2> stderr.txt # redirect the stdout to a file and the stderr to another file 

# stdin ( < )
cat < file.txt # redirect the file contetnt to the cat command

# redirect multi lines to command , The EOF in this example acts as a delimiter
cat << EOF
Black Hat Bash
by   
EOF

ls -l | grep "bin" # pip
```
### Positional arguments 
```bash
# Passing arguments to a script:
script_name=${0} ; target=${1}
echo "running script ${script_name} against target ${target}" 
# ./ping_script.sh 127.0.0.1 > echo "running script ${script_name} against target ${target}"
$?         | returen the exit code 
${0}       | the name of script file 
${1},${2}  | Positional arguments 
${#}       | the total numbers of positional arguments 
${*}       | all positional arguments (in one line)
${@}       | all positional arguments (in separte lines where avery positional argumetns quoted)
```
### input prompting
```bash
echo "what is your name?" ; read -r name ; echo "your name is ${name}" # read -r variable
```

### Exit codes 
```bash
0 -> seccess , 1 -> failure # (0-255)
whoami ; echo "the exit code was $?"
echo "exit code 233" ; exit 233 ; echo $? #  setting script exit code 
```
