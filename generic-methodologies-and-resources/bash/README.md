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
cmd1 && cmd2      # Run cmd2 only if cmd1 succeeds
cmd1 || cmd2      # Run cmd2 only if cmd1 fails
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
ls /jajaja/ja ; echo "the exit code was $?"
echo "exit code 233" ; exit 233 ; echo $? #  setting script exit code 
```


# Flow control and text processing 
## Test operators 
### Files test operators 
```bash
test [option] <file>
-d #Checks whether the file is a directory
-r #Checks whether the file is readable
-x #Checks whether the file is executable
-w #Checks whether the file is writable
-f #Checks whether the file is a regular file
-s #Checks whether the file size is greater than zero
```
### string comparison operators 
```bash
=   #Checks whether a string is equal to another string
==  #Synonym of = when used within [[ ]] constructs
!=  #Checks whether a string is not equal to another string
<   #Checks whether a string comes before another string (in alphabetical order)
>   #Checks whether a string comes after another string( in alphabetical order)
-z  #Checks whether a string is null
-n  #Checks whether a string is not null
```

### Integer Comparison Operator 
```bash
-ep # check if the number is eqaul to another number
-ne # Checks whether a number is not equal to another number
-ge # Checks whether a number is greater than or equal to another number
-gt # Checks whether a number is greater than another numbe
-lt # Checks whether a number is less than another number
-le # Checks whether a number is less than or equal to another number
```
### if condition 
```bash
if [[ condition ]] ; then 
  # do somthing 
else 
  # do something
fi
----------------------------
#  files
filename="file.txt"
if [[ -f "${filename}" ] ; then
  echo "file ${filename} existe !!"
  exit 1
else
  touch "${filename}"
  fi  
----------------------------
# the NOT Operatour (!)
filename="file.txt"
if [[ ! -f "${filename}" ]] ;then 
  touch file.txt
fi
----------------------------
#  strings 
variable1="ahmed" ; variable2="ahmxed"
if [[ "${variable1}" == "${variable2}"  ]] ;then
  echo "there are eqaul"
fi
----------------------------
var1="1" ; var2="2"
if [[  "${var2}" -gt "${var1}" ]] ;then
  echo "${var2} greater then ${var1}"
```
#### Linking Condition 
AND (***&&***) , OR (***||***) 
```bash
echo "hello" > file.txt
if [[ -f "file.txt" ]] && [[ -s "file.txt" ]] ;then 
echo "OK"
fi
```
#### Testing Command success
```bash
if [command]; then 
  # command success 
fi  

#example
if touch file.txt; then 
  echo "file created"
fi  
```
#### checking subsequent condition
```bash
user_input=${1} 
if [[ -z "${user_input}" ]]; then 
  echo "you should provid an argument"
fi

if [[ -f "${user_input}" ]]; then
  echo "the argument is a file"
elif [[ -d "${user_input}" ]]; then
  echo "the file is directory"
else
echo "${user_input} is not file and not a directory"
fi
```

### functions 
```bash
hello() {
echo "hello"
}
hello
```
#### return values 
```bash
# this function check if the user is root
check_root() {
if [[ "${EUID}" -eq "0" ]] ; then
  return 0
else 
  return 1
fi
}
if check_root; then 
  echo "root"
else 
  echo "not root"
fi
```
#### accepting  the arguments 
```bash
print_args() {
echo "${1} ${2} ${3}"
}
print_args ahmed mido levi
```
### Loops
#### while 
```bash
while some_condition; do
  # run commands 
done  

#example
while true; do
  echo "looping.."
  sleep 2
done  

# example 2
file='stop_loop.txt'
while [[ ! -f "$file" ]]; do
  echo "file not exist "
  echo "check the file again.."
  sleep 2
done 
echo 'file exist'
```
#### until 
```bash
until [[ condition ]]; do 
  # run commands until the contition is no longer false 
done  

#example 1
file="output.txt"
touch ${file}
until [[ -s "${file}" ]]; do
  echo "file is empty"
  echo "check again after 2 secounds.."
  sleep 2
done 
echo "file is not empty.."
```
#### for 
```bash 
for variable_name in LIST; do
# Run some commands for each item in the sequence.
done

#example 1 
for index in $(seq 1 10); do
  echo ${index}
done

#example 2 
for ip in ${@}; do 
  echo "taking some action on the ip address ${ip}"
done

#example 3
for file in $(ls .); do
  echo "file : ${file} ""
done
```
#### break and continue
provides an alternative to the exit command
```bash 
# break
while true; do
  echo "looping.." 
  break
done   

#continue
touch file1 file2 file3
files="$(ls . | grep file)"
echo ${files}
for file in ${files};do
  if [[ "${file}" == "file1" ]]; then
    echo "Skipping the first file"
    continue
  fi
  echo "${RANDOM}" > "${file}"
done
```
#### case
```bash
case EXPRESSION in
PATTERN1)
# Do something if the first condition is met.
;;
PATTERN2)
# Do something if the second condition is met.
;;
esac

#xeample 
ip=${1}
case ${ip} in 
  192.168.*)
    echo "the ip in in local network"
 ;;
  168.*)
    echo "the netwok 2"
 ;; 
 *)
   echo "network undifined"
esac
```
### text processing 
#### grep (extract lines)
```bash
grep "35.237.4.214" log.txt
grep "162.158.203.24\|73.166.162.225" log.txt # multiple grep patterns
grep -e "162.158.203.24" -e "73.166.162.225" log.txt
grep -i "test" test.txt # insensi-tive  search
grep -v "test" test.txt # exclude lines containing test
```
#### filtering (extract content)
```bash
awk '{print $1}' log.txt # extracte only the first word 
awk '{$1,$2}' log.txt #we can print additional fields
awk '{print $1,$NF}' log.txt # print the first and last field
awk -F',' '{print $1}' example_csv.txt #change the default delimiter to ","
grep "42.236.10.117" log.txt | awk '{print $7}' # combine grep and awk. For example, you might want to first find the lines in a file containing the IP address 42.236.10.117 and then print the HTTP paths requested by this IP:

cut -f 1 -d ":" 

```
#### sed (modify)
```bash
sed 's/Mozilla/Godzilla/g' log.txt > > newlog.txt # replace  Mozilla  with Godzilla
sed 's/ //g' log.txt # remove any whitespace
sed '1d' log.txt # delect the first line
sed '$d' log.txt # delete the last line
sed '5,7d' log.txt # delect the line 5 and 7 
sed -i '1d' log.txt # -i argument, it will make the changes to original file

# tr
echo "HELLO WORLD" | tr 'A-Z' 'a-z' # Convert Uppercase to Lowercase
echo "hello123world" | tr -d '0-9' #Delete Specific Characters
echo "aaabbbccc" | tr -s 'abc' #Remove Duplicate Characters
```
### job control 
```bash
sleep 100 & # run command in the background
ps -ef | grep sleep  # check the command runnin gin the background
jobs # get the  background  commands id ex.(id =1 )
fg %1 # migrate the job from backgroud to foreground 
CTRL+Z # suspend the process 
bg %1 #  send the process to the background again
nohub [command or script] & # keeping jobs running after logout or exit from the terminal 
```
### bash customizing  for penetration testing
```bash
alias test="nmap localhost" ; test # shortening the commmand to save time
# set a value in terminal
test="127.0.0.1" # exit adn open new terminal 
source ~/.bashrc 
echo ${test}
# importing custom bash sesssion file
source ./file.sh #OR using the dote ". ./file.sh"

#Capturing Terminal Session Activity
#!/bin/bash
FILENAME=$(date +%m_%d_%Y_%H:%M:%S).log
if [[ ! -­d ~/sessions ]]; then
mkdir ~/sessions
fi
# Starting a script session
if [[ -­z $SCRIPT ]]; then
export SCRIPT="/home/kali/sessions/${FILENAME}"
script -­q -­f "${SCRIPT}"
fi

#Penetration testing often involves having dozens of terminals open simulta-
neously, all running many tools that can produce a lot of output. When we
find something of interest, we may need some of that output as evidence for
later. To avoid losing track of an important piece of information, we can use
some clever bash.
The script command allows us to capture terminal session activity. One
approach is to load a small bash script that uses script to save every session
to a file for later inspection,Having ~/.bashrc load this script, as shown earlier, will result in the cre-
ation of the ~/sessions directory, containing each terminal session capture in
a separate file. The recording stops when you enter exit in the terminal or
close the terminal window.
```