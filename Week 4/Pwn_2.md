---
###### tags: `Hackersir note`
---
# Pwn_2
## Protection

### Stack Guard
做完 function prologue 的時候會將隨機生成的亂數塞入stack 中， function return 前會檢查該亂數是否有被更動過，若發現更動就立即結束程式，又稱 canary。

### DEP
Data execution prevention，可執行的地方不能寫，可寫的地方不能執行，又稱 NX。

### ASLR
Address Space Layout Randomization，每次程式執行時 stack, heap, library 位置都不一樣，有效防禦return to text。

### PIE
Position Independent Execution，開啟後，code 與 data 都會跟著 ASLR，用objdump分析時，會無法得到確切的address。

## GOT Hĳacking

### Lazy Binding
因為不一定每個 library function 都會被執行到，所以採用lazy binding 機制，當第一次執行到 library function 時才會去尋找真正的 address 並進行 binding。

### Global Offset Table
GOT 為 library function 的指標陣列，因為 lazy binding 機制，因此一開始不會知道真實位置，取而代之的是擺 plt 段的 code。
GOT在data端，plt在code端。

第一次Call function 時不會直接去的address，而是function 的plt。
```
0000000000400550 <function@plt>:
400550: jmp QWORD PTR [0x601018] <function@GOT>
400556: push 0x0
40055b: jmp 400540 <.plt>
```
1. 先jump 到GOT上的位置，然後又從GOT跳回``function@plt+6``，也就是上面第二行。
2. push index。
3. jump 到 plt 上，然後會 call ``<_dl_runtime_resolve_xsave>`` 的function，GOT 上的``<function@GOT>``就會擺上真正的function address。
4. 之後再call就會從GOT跳上真正的位置了。

:::info
思路：
如果我們可以修改GOT，那之後call function是不是要可以跳上我們要去的地方?
:::

### RELRO
Relocation Read-Only
* Partial RELRO
    * GOT 可寫
* Full RELRO
    * Load time 時會將所有 function resolve 完畢
    * GOT 不可寫

## ROP
Return Oriented Programming，透過不斷去執行包含 ret 的程式片段來達到想要的操作，這些包含 ret 的程式片段又被稱作 gadget。

```
4004fa: 48 83 c4 08     add rsp, 0x8
4004fe: c3              ret

4005b8: 5d              pop rbp
4005b9: c3              ret

4006c4: c9              leave
4006c5: c3              ret

400730: 41 5e           pop r14
400732: 41 5f           pop r15
400734: c3              ret

400730: 41 5e           pop r14
400732: 41 5f           pop r15
400734: c3              ret

400731: 5e              pop rsi
400732: 41 5f           pop r15
400734: c3              ret

400732: 41 5f           pop r15
400734: c3              ret

400733: 5f              pop rdi
400734: c3              ret
```

### ROP Chain
由眾多的 ROP gadget 所組成的，可以藉由不同 ROP gadget 的小功能串成任意代碼執行的效果，取代 shellcode 攻擊。

### Example
1. 今有一 rip 已執行到 ``ret``，而 rsp 是``0xdeadbeef``。
2. 若把原本的``0xdeadbeef``改成``0x415294``，而這一 address 是原本程式裡的一小段 code，所以 rip 會追進``0x415294``，執行``pop rax ; ret``。
3. 通常會把你要把帶進去 rax 的值寫在後面，例如：``0x3b``，這樣上面執行``pop rax``，就能順利把``0x3b``寫入 rax。
4. 之後又 return 回 stack，rsp 又被我們修改成``0x474a65``，當然也是程式裡的片段，執行``syscall ; ret``。
5. 根據 linux syscall table，call syscall 時 rax 是 3b 會是function execve。

## Return to libc
一般程式很少有 system，execve 或是後門程式，在 DEP 保護下無法執行填入的 shellcode，libc 有許多可以利用的 function 片段，讓我們可以使用system 或 execve 等開 shell
```cpp=
#include <sigsetops.h>
#define SHELL_PATH "/bin/sh" /* Path of the shell. */
#define SHELL_NAME "sh" /* Name to give it. */
(void) __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL);
INIT_LOCK ();
...
/* Exec the shell. */
(void) __execve (SHELL_PATH, (char *const *) new_argv, __environ);
```
因為 ASLR，每次 libc 載入的位置都不同，所以我們只要把某個function 的 address 找出來扣掉 offset 的值，就是 libc 的 base address，之後再加上已知的 offset 就可以順利的 call function。


