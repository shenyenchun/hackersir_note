# Reverse 0x01
## Basic
* 檔案類型
```bash=
$ file <something> //查看檔案的類型
```

* 包含字串
看執行檔內的字串且使用 grep 搜尋
```bash=
$ strings <something> //印出檔案中的可視字串
```
```bash=
$ strings -n <min-len> <something> //印出長度最短為 min-len 的可視字串
```

```bash=
$ strings <something> | grep "puts" //在 strings 的結果中有包含 "puts" 字串的結果
```

* objdump
看執行檔的組合語言
```bash=
$ objdump -M intel -d <binary> //以 intel 格式顯示 binary 反組譯的結果 (組合語言)
```
```bash=
$ objdump -M intel -d <binary> | less //把輸出結果導向到 less 方便查詢閱讀
```
:::info
$ alias objdump=”objdump -M intel”
:::

* strace / ltrace
system call 和 library call 的差別
```bash=
$ strace <binary> \\查看 binary 執行時的 system call 和 signal
```
```bash=
$ ltrace <binary> \\查看 binary 執行時的 library call
```
:::danger
做ltrace實作時被permission denied
sudo也無解
:::
## x64 組合語言
### Registers
![](https://i.imgur.com/dTRq2Wh.jpg)

* rax - accumulator。用在算術運算。
* rbx - base。作為一個指向資料的指標（在分段模式下，位於段暫存器DS）。
* rcx - count。用於移位/迴圈指令和迴圈。
* rdx - data。用在算術運算和I/O操作。
* rsi - source index。在流操作中用作源的一個指標。
* rdi - destination index。用作在流操作中指向目標的指標。
* rbp - base pointer。用於指向堆疊的底部。
* rsp - stack pointer。用於指向堆疊的頂部。
### assembly language
* mov
    * syntax
         ```basic=
        mov 目的,來源
        ```
    * example
        ```basic=
        mov rax,rbx           //rax=abx
        mov rax, [rbp - 4]    //rax = *(rbp - 4)
        mov [rax], rbx        // *rax = rbx
        ```
* add、sub、imul、idiv、and、or、xor
    * syntax
         ```basic=
        add 目的,來源
        ```
    * example
        ```basic=
        sub rbx, [rbp - 4] // rbx = rbx - *(rbp - 4)
        mul rcx, 2         // rcx = rcx * 2
        xor [rsp], rax     // *rsp = (*rsp) ^ rax
        ```
* inc、dec、neg、not
    * syntax
        inc 目的
    * example
        ```basic=
        dec rbx					// rbx = rbx - 1
        neg rcx					// rcx = -rcx
        not byte [rsp]	    	// convert [rsp] to byte
							       *rsp = ~(*rsp)
        ```
* if destination is memory access and source is not register, need to specify the dest’s type and destination and source must be the same type

    * example
        ```basic=
        mov byte [rcx], 0x61		// byte = 8 bits
        mul word [rax], 0x87		// word = 2 bytes
        inc dword [rbp]				// dword = 2 words
        not qword [rsp]				// qword = 2 dwords
        ```
* cmp
    * syntax
        ```basic=
        cmp value1, value2
        ```
    * example
        ```basic=
        cmp rax, 5		// compare the values and set the flag
        cmp rbx, rcx
        cmp word [rsp], 0x1234
        ```
* jmp 無條件跳越
    * syntax
        ```basic=
        jmp label
        ```
    * example
        ```basic=
        loop:			// set a label
        ; do something
        jmp loop		// jump to loop label
        ```
* ja(x > y)
* jb(x < y)
* jna(x ≦ y)
* jae(x ≧ y)
* je(x = y)
* jne(x ≠ y)
* jz(= 0)
    * syntax
        ```basic=
        ja label
        ```
    * example
        ```basic=
        cmp rax, 10		// compare the values and set flag
        je quit			// check flag if equal jump to quit
        ```
* nop
    * syntax
        ```basic=
        nop
        ```
* push & pop
    * syntax
        ```basic=
        push source
        pop dest
        ```
    * example
        ```basic=
        push rax
        push 0
        pop rcx
        pop word [rbx]
        ```
* syscall
    * syntax
        ```basic=
        syscall
        ```
    * example
        [LINUX SYSTEM CALL TABLE FOR X86 64 (http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)

## 組合語言與 C 的轉換
### conditional statement
```c=
if (rax < 5){
    //do something
}
else if (rax >= 5 && rax < 10){
    //do something
}
else{
    //do something
}
```
```basic=
cmp rax,5
jae Lelseif
; do something
jmp Lend

Lelseif:
cmp rax,10
jae Lelse
;do something
jmp Lend

Lelse:
;do
something

Lend:
```
### loop
```c=
for (int i = 0;i < 10; i++){
    //do something
}
```
```basic=
mov rcx,0
Lloop:
cmp rcx,10
jae Lend
;do something
inc rcx
jmp Lloop
Lend:
```
## Compile
```bash=
nasm -f elf64 <asm source code>
```
* -f elf64   //output elf 64 format
```bash=
ld -m elf_x86_64 -o <output file name> <object file>
```
* -m elf_x86_64   //elf x86-64 format
* -o    //output file name
## Disassemble
```bash=
objdump -M intel -d <binary file>
```
* -M intel  //intel syntax
* -d    //disassemble
:::success
我還是用IDA pro
:::