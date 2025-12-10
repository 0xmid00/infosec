## 2.1 introduction
assembly (OPCODE) it low level lang and it still need to be converted into machine code to be executed 
## 2.2 Assembler
- An assembler is a program that translates the Assembly language to the machine code
- When a source code file is assembled, the resulting file is called an object file. It is a binary representation of the program.
- To produce a final executable, a **linker** is used. It combines one or more object files into an executable and links required libraries (e.g., kernel32.dll, user32.dll on Windows).
- we will use the NASM Assembler Programme  
![[Pasted image 20251209202310.png]]

## 2.3 Compiler 
The complier is similar to the assembler. It converts high-level source code (such as C) into low-level code or directly into an object file. then **linker** is used. It combines one or more object files into an executable and links required libraries (e.g., kernel32.dll, user32.dll on Windows).

## 2.4 NASM 
The assembler we are going to use is NASM, and to make things easier, we will use the [[forum.nasm.us/index.php?topic=1853.0| NASM-X project.]]
#### 2.4.1 Installation Instruction
 - Download the .zip file from [[https://sourceforge.net/projects/nasmx/ |here]] , and extract  it to `C:\nasmx `
 - add the`C:\nasmx\bin` to the PATH 
 - execute the `c:\nasmx\setpath.bat`
 - in `C:\nasmx\demos\windemos.inc` file replace `%include 'nasmx.inc'` with `%include 'C:\nasmx\inc\nasmx.inc'
 
 in the `C:\nasmx\demos\win32\DEMO1` there is the assembly file `demo1.asm`:
**create the object file  of the asm file :**
```cmd
nasm -f win32 demo1.asm -o demo1.obj
  #=> demo1.obj
```
**use the linker to link the `demo1.obj`files with the libs:**
```cmd
GoLink.exe /entry _main demo1.obj kernel32.dll user32.dll 
  # => demo1.exe
```
now execute the demo1.exe programme
```cmd
.\demo1.exe
```
![[Pasted image 20251209213515.png]]
### 2.4.2 ASM Basics 
Most instructions have two operands and fall into one of the following classes:
![[Pasted image 20251209213629.png]]
example code: of the sum `2+5`
```asm
MOV EAX,2   ; store 2 in EAX
MOV EBX,5   ; store 5 in EBX
ADD EAX,EBX ; do EAX = EAX + EBX operation
            ; now EAX contains the results EAX=7
```

#### 2.4.2.1 Intel vs AT&T
ASAM instructions and rules in Intel and AT&T(Linux) may deference . example:
![[Pasted image 20251209214105.png]]
#### 2.4.2.2 PUSH 
**PUSH** stores a value to the top of the stack, causing the stack to be adjusted by -4 bytes (on 32 bit systems): -0x04.
![[Pasted image 20251209214424.png]]

same operation (`PUSH 0x12345678`) can be achieved in a different way:
```asm
SUB ESP, 4             ; subtract 4 to ESP -> ESP=ESP-4
MOVE [ESP], 0x12345678 ;store the value 0x12345678 to the location
                       ;pointed by ESP. Square brackets indication address pointed by the register.
```
#### 2.4.2.3 POP
**POP** reads the value from the top of the stack, causing the stack to be adjusted +0x04.
![[Pasted image 20251209214842.png]]
The POP operation can also be done in several other instructions:
```asm
MOV EAX, [ESP] ;store the value pointed by ESP into EAX , the value at the top of the stack
ADD ESP,4      ;Add 4 to ESP – adjust the top of the stack
```

#### 2.4.2.4 CALL Instruction
The **CALL** instruction pushes the current instruction pointer (EIP) to the stack and jumps to the function address specified. Whenever the function executes the RET instruction, the last element is popped from the stack, and the CPU jumps to the address.
![[Pasted image 20251209215315.png]]
## 2.5 Tools Arsenals 
we will use different tools and software. The most important are the C/C++ compilers and the debuggers. 
### 2.5 Compilers
you will need a compiler when writing c/c++ codes, we will use IDE to manages all files some of them can be : Microsoft Visual C/C++ (Visual Studio) or free software like Orwell Dev-C++, or Code::Blocks and so on. For our purposes, Dev-C++ is enough

 after install the Dev-C++  it  will  create a directory `MinGw64`   where all the compiling tools are stored. add the bin in `Program Files (x86)\DEV-CPP\MinGW64\bin` to your windows environment variables so u can use gcc from the cmd
![[Pasted image 20251210150207.png]]
To compile the C file using gcc we can run the following command:
```cmd
gcc -m32 HelloStudents.c -o HelloStudents.exe
```

> It is important to know that every compiler will produce a slightly different output. Therefore, the same source code compiled with different compilers (such as Microsoft Visual Studio, MinGW, GCC, etc.) may produce different machine codes.
### 2.5.2 Debuggers
A debugger is a program which runs other programs, in a way that we can exercise control over the program itself , help us to write exploits, analyze programs, reverse engineer binaries and much more. the debugger allows us to:
- Stop the program while it is running
- Analyze the stack and its data
- Inspect registers
- Change the program or program variables and more

some example of debuggers: IDA (Windows, Linux, MacOS), GDB (Unix, Windows), X64DBG (Windows), EDB (Linux), WinDBG (Windows), OllyDBG (Windows), Hopper (MacOS, Linux)

we will use **Immunity Debugger**
![[Pasted image 20251210151557.png]]
**panel 1:** the main window where all the Assembler code is produced
-  In the first column is the address location
-  In the second column is the machine code
- In the third column is the assembly language
-  In the fourth column is the debugger comments

**Panel 2:** As the program progresses and registers are changed or updated, it is easily noted and observed in this panel.

**Panel 3:** The Memory Dump Panel shows the memory locations and relative contents in multiple formats (i.e., hex, UNICODE, etc.).
Panel 4: The Stack Panel shows the current thread stack.
- In the first column is the addresses
-  In the second column is the value on the stack at that address
- In the third column is an explanation of the content (if it's an address or a UNICODE string, etc.)
-  In the fourth column is the debugger comments
### 2.5.3 Decompiling 
if we want to inspect the executable program `.exe` in order to get the assembly code of it and  understand it  we will  need to `decompile ` it 

there is many tools to do that but in the Dev-C++ Folder `Program Files (x86)\DEV-CPP\MinGW64\bin` there is a executable program `objectdump.exe` for to disassemble executable programs (show the assembly code of it)

command to decompile
```cmd
objdump -d -Mintel HelloStudents.exe > disasm.txt
```
disasm.txt, containing the assembly code of the program.
>Notice that this is something that a debugger like Immunit Debugger automatically does.(in the Panel 1)

