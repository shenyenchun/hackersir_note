###### tags: `Hackersir note`
# Reverse 0x02
## GDB
### Install
[peda](https://github.com/longld/peda)
[Pwngdb](https://github.com/scwuaptx/Pwngdb)
```bash=
$ git clone https://github.com/longld/peda.git ~/peda
$ echo "source ~/peda/peda.py" >> ~/.gdbinit
$ git clone https://github.com/scwuaptx/Pwngdb.git ~/Pwngdb
$ cp ~/Pwngdb/.gdbinit ~/
```
### Method
* 執行 binary 並且使用 gdb 來 debug
    ```bash=
    $ gdb <binary>
    ```
* 先執行 gdb 之後再 attach 上要 debug 的 process
    ```bash=
    $ gdb
    attach <pid>
    a
    ```
### GDB Commamd
* 設定斷點
    ```
    break <address>
    b <address>
    break *0x0000000004004d7
    ```
* 執行程式
    ```
    run
    r
    ```
* 執行下一個指令 (會追進 function)
    ```
    step
    si
    ```
* 執行下一個指令 (不會追進 function)
    ```
    next
    ni 
    ```
* 繼續執行
    ```
    continue
    c
    ```
* 執行至 function 結束
    ```
    finish
    ```
* 跳轉
    ```
    jump <address>
    jump *0x0000000004004d7
    ```
* 印出暫存器的值
    ```
    print <register>
    print $rax
    ```
* 印出記憶體的值
    ```
    x <memory address>
    x 0x7fffffffe920
    ```
* 改變暫存器的值
    ```
    set <register>=<value>
    set $rsp=0x7fffffffe800
    ```
* 改變記憶體的值
    ```
    set {<size>}<memory address>=<value>
    set {int}0x7fffffffea00=2
    ```
### GDB Feature
* checksec
    * 查看binary中的保護機制
* elfsymbol
    * 查看function .plt做ROP時很重要
* vmmap
    * 查看process mapping，可觀察每個address中的權限
* readelf
    * 查看section位置
* find/searchmem
    * search memory中的patten
* record
    * 紀錄每個instruction讓GDB可回朔前面的指令，追回發生問題的地方
* [GDB Online Document](https://sourceware.org/gdb/onlinedocs/gdb/index.html)

## IDA Pro
### 反編譯
將binary反編譯回C
在function windows在function windows點選要看的function，按下F5就可反編譯

### 字串表
* view -> Open subviews ->String
* shift+F12
 
### 標記
* 標記變數名
    先點擊要標記的變數，按下n，輸入標記的名字
* 標記function參數
    先點擊function，按下y，輸入要改的function參數
* 標記struct結構
    切到struct頁面，新增struct並標記內容

## Reverse Solution
1. 先用objdump找cmp的address
2. 設GDB break，然後執行
3. 觀察執行到的位址
4. 觀察暫存器裡的值
5. 更改暫存器成要判斷的條件然後執行