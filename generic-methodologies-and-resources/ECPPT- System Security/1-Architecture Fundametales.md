## 1.1 introduction
- Focus: Windows, x86/x64 architectures, assembly, compilers
- Security: ASLR, DEP
- Techniques: Buffer Overflows (BOF), fuzzing, reverse engineering
## 1.2 Architecture Fundametales
### 1.2.1 CPU,ISA,Assembly
**CPU →** Executes machine code.  
**Machine Code →** Binary/hex CPU instructions.  
**Instruction →** Basic CPU operation (data, arithmetic, flow).  
**HEX →** Human-unfriendly machine code format.  
**Assembly (ASM) →** Mnemonics for machine code or operation code (`opcode`)
**NASM →** Netwide Assembler used here.  
**Disassembly →** Machine code → ASM.  
**ISA →** CPU instruction set (registers, memory, ops).  
**x86 →** 32-bit CPU ISA.  
**x64 →** 64-bit CPU ISA.

```bash
# ===== 32-bit Registers & Memory =====

# 1. 32-bit Register = 4 bytes
[31..........................0] = 32 bits = 4 bytes
Byte layout: | byte1 | byte2 | byte3 | byte4 |

# 2. Memory Dump
register = 4 bites = 32bites 
Format: [byte1]-[byte2]-[byte3]-[byte4]

# 3. Hex Representation
chat A; = 1 byte = 2 hex digits (e.g., 4F)
int A; = 4 bytes = 8 hex digits (e.g., 0x01020304)

# Example Hex for number 1234
Addr   Hex
0x1000 01
0x1001 02
0x1002 03
0x1003 04

# Example Hex for 'HELLO'
Addr       Hex  Char
0x00404000 48   H
0x00404001 45   E
0x00404002 4C   L
0x00404003 4C   L
0x00404004 4F   O

# 4. Register Visualization
ESP = 0x01020304
+---+---+---+---+
|01 |02 |03 |04 |
+---+---+---+---+
byte1 byte2 byte3 byte4 (8b each)
```
### 1.2.2 Registers
 x86 General Purpose Registers
```
# +-----+------------------------------+
# |Reg  | Purpose                      |
# +-----+------------------------------+
# |EAX  | Accumulator (arithmetic)     |
# |ECX  | Counter (loops, shift/rotate)|
# |EDX  | Data (arithmetic, I/O)       |
# |EBX  | Base (data pointer)           |
# |ESP  | Stack Pointer (top of stack) |
# |EBP  | Base Pointer (stack base)     |
# |ESI  | Source Index (source pointer) |
# |EDI  | Destination (dest pointer)   |
# +-----+------------------------------+
```
- also  **The Instruction Pointer (EIP)** controls the program execution by storing a pointer to the address of the next instruction (machine code) that will be executed.
### 1.2.3 Process memory
```bash
# ===== Memory Layout Diagram (Low → High) =====
# Low memory addresses
# 0x00000000
# +--------------------------+
# |        Text              | <- program instructions (machine code)
# |   main(), foo(), etc.    |
# +--------------------------+
# |        Data              | <- initialized globals/statics
# |   static int x = 10;     |
# |   int y = 20;            |
# +--------------------------+
# |         BSS              | <- uninitialized globals/statics (0)
# |   static int a;          |
# |   int b;                 |
# +--------------------------+                    Heap grows ↓
# |        Heap              | <- dynamically allocated memory
# |   int *ptr = malloc(10*sizeof(int)); |
# +--------------------------+ ESP (the top)       Stack grows ↑ 
# |        Stack             | <- local variables, function calls,return address
# |   int local = 5;         | <- grow downward from high memory -> low memory  
# +--------------------------+ EBP (the base)
# High memory addresses
# 0xFFFFFFFF
```
==***Stack:***==
- **Automatic allocation:** Memory is **automatically allocated** when a function is called.
- **Automatic deallocation:** Memory is **freed automatically** when the function returns.

==***Heap:***==
- **Manual allocation:** Programmer explicitly allocates memory using **`malloc` / `calloc` / `realloc`**.
- **Manual deallocation:** Programmer must free memory using **`free()`**; otherwise, it causes **memory**

==**Variable Access:**==
- **Local (stack)** → Stack : `[EBP/ESP - offset]`
- **Global/Static** → Data/BSS : Absolute address, accessed via registers
- **Dynamically allocated** → Heap : Pointer in register, access via pointer + offset
- **CPU registers** → Registers : Direct access by name (fastest)

### 1.2.4 The Stack
- **Stack = LIFO memory** for return addresses, args, locals
- **Location:** high memory, grows downward
- **ESP:** points to top of stack; PUSH → ESP−4, POP → ESP+4
- **Heap vs Stack:** Heap grows up, Stack grows down
- **Operations:** PUSH = add value, POP = remove  to register
#### 1.2.4.1 PUSH Instruction
**PUSH →** Subtracts 4 (32-bit) / 8 (64-bit) from ESP, stores data at new ESP addr , stack grows downward to avoid overwriting top.
example:
```bash
# ESP = 0x0028FF80
PUCH 1
# ESP - 4 = 0x0028FF80 - 4 = 0x0028FF7C

# 0x0000 (LOW)                PUCH 1-->
                | ..      |  ESP 0x0028FF7C |0x00000001|  <- ESP
ESP 0x0028FF80  |   ..    |                 |   ..     |
                |   ..    |                 |    ..    |
            EBP |    ..   |                 |     ..   | EBP
# 0xFFFFF  (HIGH)
```
#### 1.2.4.2 POP Instruction
```bash
# ESP = 0x0028FF7C 
POP EAX
# ESP + 4 = 0x0028FF7C + 4 = 0x0028FF80
EAX = 0x00000001

# 0x0000 (LOW)               POP EAX -->
 ESP 0x0028FF7c | AAAA    |                  |   AAAA   |
                |   ..    |   ESP 0x0028FF7C |    ..    |  <- ESP
                |   ..    |                  |    ..    |
            EBP |    ..   |                  |     ..   | EBP
# 0xFFFFF  (HIGH)
```
#### 1.2.4.3 Procedure and Functions 
- When a value is popped from the stack, it’s **not erased** , it stays there until something overwrites it.
- Procedures/functions **change the normal program flow**.
- When they finish, they **return control** back to the instruction that called them.
#### 1.2.4.4 Stack Frames 
Stack frames are created and removed as functions call each other (main → a → b) and return, showing how control flow and the stack pointer move during program execution.
example:
```c
int b(){ //function b
return 0;
}
int a(){ // function a
b();
return 0;
}
int main (){//main function
a();
return 0;
}
```
![[Pasted image 20251208203114.png]]

---

we need to go into more detail as to what information is stored, where it is stored and how the registers are updated.
This second example is also written in C.
```c
void functest(int a, int b, int c) {
int test1 = 55;
int test2 = 56;
}
int main(int argc, char *argv[]) { 
int x = 11;
int z = 12;
int y = 13;
functest(30,31,32);
return 0;
}
```
![[Pasted image 20251208203859.png]]
1. Program starts → `argc` and `argv` are pushed onto the stack.
2. CPU executes `CALL main()` and pushes the return address (`EIP`) onto the stack.
3. The caller (the instruction that executes the function calls - the OS in this case) loses its control, and the callee (the function that is called - the main function) takes control.
4. Old `EBP` is saved on the stack and `EBP` is updated to create the new stack frame.

#### 1.2.4.5 Prologue
The previous step is known as the prologue: it is a sequence of instructions that take place at the beginning of a function `main()`, 
```asm 
push ebp                         ; EBP = ESP 
mov ebp, esp                     ; save old ESP addr 
sub esp, X // X is a number      ; allocate stack spce
```
![[Pasted image 20251208215156.png]]
**push ebp** Saves the previous base pointer `EBP` (old stack frame base) in the Top of the Stack.
**mov ebp, esp** Sets `EBP` to the current `ESP`, creating a new stack frame base.
**sub esp, X** Allocates space for local variables by decreasing ESP (stack grows downward).

now after the **Prologue** the main function will save the variables (`x=11,z=12,y=13`) , The instructions after the prologue are like the following:
```asm
MOV DWORD PTR SS:[ESP+Y],0B
```
move the value 0B (hexadecimal of 11 - the first local variable) into the memory address location pointed at ESP+Y. Note that Y is a number and ESP+Y points to a memory address between EBP and ESP.

5. move the value 0B (hexadecimal of 11 the first local variable) into the memory address location pointed at ESP+Y. Note that Y is a number and ESP+Y points to a memory address between EBP and ESP. 

This process will repeat through all the variables, and once the process completes, the stack will look like the following:
![[Pasted image 20251208222556.png]]

Then the `main()` continues executing its instructions. next instruction calls the function` functest()`. 
- `main()` calls `functest()`.
- New stack frame is created:
    1. Push function parameters.
    2. Call `functest()` → old EIP pushed.
    3. Execute prologue (`push ebp; mov ebp, esp; sub esp, X`).
    4. Allocate local variables on the stack.

the entire process stack will look like this :
![[Pasted image 20251208222848.png]]
#### 1.2.4.6 Epilogue
The following code represents the epilogue:
```asm
leave
ret
```
The instructions can also be written as follows:
```asm
mov esp, ebp  ; both ESP and EBP point to the same location
pop ebp       ;  POPS the value from the top of the stack into EBP
ret           ; ops the value contained at the top of the stack to the old EIP
              ; then and jumps to EIP location    
```
have to understand how the stack destroyed, this happen when the function end and return 
what Epilogue do:
  - 1- Replace the stack pointer with the current base pointer. It restores its value to before the prologue; this is done by POPping the base pointer from the stack. `new EBP=EBP content`
- 2- Returns to the caller by POPping the instruction pointer from the stack (stored in the stack) and then it jumps to it. `new EIP = POP (TOP OF STACK) to EIP `

### 1.2.5 Endianness
**Endianness** is the way of representing (storing) values in memory. there are 3 types but we will cover 2 types : `big-endian` and `little endian`

**The most significant bit (MSB):** in a binary number is the largest value, usually the first from the left. So, for example, considering the binary number 100 the MSB is 1
**The least significant bit (LSB)** in a binary number is the lowest values, usually the first from the right. So, for example, considering the binary number 110 the LSB is 0

 **big-endian:** representation, the least significant byte (`LSB`) is stored at the `highest memory `address. While the most significant byte (`MSB`) is at the `lowest memory address`.
 - example: `0x12345678` : `LSB`=78 stored in` high memory`  ,`MSB` = 12 stored in `low memory`![[Pasted image 20251209003426.png]]

 **little-endian:** representation  therefore, the `LSB` is stored in the` lower memory` address, or `MSB` is stored at the `highest memory` address.
 - example: `0x12345678` : `LSB`=78 stored in` low memory`  ,`MSB` = 12 stored in `high memory`![[Pasted image 20251209003442.png]]

Example of the number `11` in `little-endian` representation in the dump memory:
  - 11 = `0B` in hex, so it will saved as integer (4 byte) `0x0000000B`
  - in `little-endian`: `LBS` will saved in `low memory` (exactly in addr `0028FEBC`)  ![[Pasted image 20251209003925.png]]


### 1.2.6 NOPs
- **NOP (0x90)** = CPU instruction that **does nothing**, just moves to the next instruction.
- **NOP-sled** = a sequence of many NOPs placed in memory (usually on the stack).
- Used in **buffer overflow exploits** to make it easier for the CPU to “slide” into your shellcode.
- Purpose: If the program jumps anywhere inside the NOP-sled, it will slide into your real payload.

## 1.3 Security Implementation
the security implementations that have been developed during the past several years to prevent, or impede, the exploitation of vulnerabilities such as Buffer Overflow.
-  Address Space Layout Randomization (ASLR)
-  Data Execution Prevention (DEP)
-  Stack Cookies (Canary)
### 1.3.1 ASLR
**ASLR (Address Space Layout Randomization):**  
ASLR randomizes the memory locations of executables, libraries, and the stack each time a program runs. This unpredictability makes it harder for attackers to guess memory addresses, causing many exploits to fail or crash.
 example. The application calculator (calc.exe) is opened in the debugger and has the base address of 00170000.
 ![[Pasted image 20251209005800.png]]
After rebooting the machine and reloading calculator (calc.exe) again, we can see that the base address has changed to: 01040000.![[Pasted image 20251209005840.png]]
- even if a process has ASLR enabled, there could be a DLL in the address space without this protection which could make the process vulnerable to the ASLR bypass attack.
  To verify the status of ASLR on different programs, download the Process Explorer from [[http://technet.microsoft.com/en-us/sysinternals/bb896653|here]], and verify yourself. Inour system, we can see that not all the processes use ASLR:![[Pasted image 20251209010148.png]]
  the Enhanced Mitigation Experience Toolkit [[http://blogs.technet.com/b/srd/archive/2010/09/02/enhanced-mitigation-experience-toolkit-emet-v2-0-0.aspx|EMET]].It provides users with the ability to deploy security mitigation technologies to all applications.
### 1.3.2 DEP
**Data Execution Prevention (DEP)** is a defensive hardware and software measure that prevents the execution of code from pages in memory that are not explicitly marked as executable. The code injected into the memory cannot be run from that region; this makes buffer overflow exploitations even harder , [[https://support.microsoft.com/en-us/kb/875352|more here]] 

### 1.3.3 Stack Canary (Canary)
**Stack Canary (Stack Cookie)** A stack canary is a security value placed next to the return address on the stack. 
The function prologue sets this value, and the epilogue checks if it’s unchanged.
If the value is modified, it indicates a buffer overflow attempt, since overflows usually overwrite stack data.

