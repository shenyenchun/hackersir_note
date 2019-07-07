---
###### tags: `Hackersir note`
---
# CTF Write-Up Week2
## SQL_No_whitespace
![](https://i.imgur.com/TUDONjZ.png)
直接對填入欄SQLi就噴flag了

## SQL1
![](https://i.imgur.com/7Ywx3Gm.png)
跟上面那題一樣直接SQLi就噴flag

## cookie
![](https://i.imgur.com/5VLL92c.png)
原本cookie的值是
```
a:3:{s:7:"user_id";i:38023;s:5:"admin";b:0;s:3:"iid";i:4663;}
```
把admin的b:1改成b:1，重新整理flag就出來了
## redict
用curl就噴出來了

## SJkcuF
先把JSFuck的內容翻轉
![](https://i.imgur.com/yxO8qVo.png)
然後丟到F12 Console執行，flag就噴出來了

## LFI
在page=的後面加上偽協定，網頁就不會去執行php，而是把php以base64的編碼顯示在網頁上
http://ctf.hackersir.org:10015/index.php?page=php://filter/convert.base64-encode/resource=index
之後將base64編碼反編譯至html語言就順利找到flag了

## Pwntools?
先從題目上的檔案開始分析，一開始用IDA PRO對檔案反編譯，得知裡面的code，是100題隨機生成的數學題目，然後開始寫payload
```python=
from pwn import *

#r = process("./pwntools")
r = remote("ctf.hackersir.org","10130")

for i in range(100):
        q = r.recvuntil(" =").replace(" =","")
        print q
        ans = eval(q)
        r.sendline(str(ans))

r.interactive()

```
用eval下去算數學題目（壞習慣不要學），之後再將答案回傳就找到flag了

## SQL``_\'``
code裡面有一段取代``'``成``\'``
```php=
function safe_filter($str)    {
        return str_replace("'", "\'", $str);;
    }
```
那麼只要在``' OR  "1"="1" #``前加上``\``,把取代的註解關閉就行了

## ==1
不太清楚原理，把cookie W16_data改成``==1``就有flag了

## Fake_IP
用Burp Suite攔截封包，增加X-Forwarded-For:127.0.0.1 和 Client-IP:8.8.8.8，把cookie刪除，之後forward，flag就出來了
:::success
acknowledge:
[如何正確的取得使用者 IP？](https://devco.re/blog/2014/06/19/client-ip-detection/)
:::

## [be-quick-or-be-dead-1](https://2018shell.picoctf.com/static/f825b5db114de1d3f811961b54f9cfb1/be-quick-or-be-dead-1)
先執行程式
```bash=
$./be-quick-or-be-dead-1 
Be Quick Or Be Dead 1
=====================

Calculating key...
You need a faster machine. Bye bye.
```
是一個有時間限制的計算程式，然後用IDA看
* main()
    ```cpp=
    int __cdecl main(int argc, const char **argv, const char **envp)
    {
      header();
      set_timer();
      get_key();
      print_flag();
      return 0;
    }
    ```
* set_timer()
    ```cpp=
    unsigned int set_timer()
    {
      if ( __sysv_signal(14, (__sighandler_t)alarm_handler) == (__sighandler_t)-1 )
      {
        printf(
          "\n\nSomething went terribly wrong. \nPlease contact the admins with \"be-quick-or-be-dead-1.c:%d\".\n",
          59LL);
        exit(0);
      }
      return alarm(1u);
    }
    ```
* get_key()
    ```cpp=
    int get_key()
    {
      puts("Calculating key...");
      key = calculate_key();
      return puts("Done calculating key");
    }
    ```
* calculate_key()
    ```cpp=
    signed __int64 calculate_key()
    {
      signed int v1; // [sp+0h] [bp-4h]@1

      v1 = 1876196924;
      do
        ++v1;
      while ( v1 != -542573448 );
      return 3752393848LL;
    }
    ```
思路：我們只要跳過set_timer()這個function :satisfied: :satisfied: 

### Solution
先用objdump看所有的Address，我們要找的是call set_time 的上一個function header的Address，方便我們待會用GDB的斷㸃
```bash=
00000000004007e9 <header>:
  4007e9:	55                   	push   rbp
  4007ea:	48 89 e5             	mov    rbp,rsp
  4007ed:	48 83 ec 10          	sub    rsp,0x10
  4007f1:	bf c0 09 40 00       	mov    edi,0x4009c0
  4007f6:	e8 35 fd ff ff       	call   400530 <puts@plt>
  4007fb:	c7 45 fc 00 00 00 00 	mov    DWORD PTR [rbp-0x4],0x0
  400802:	eb 0e                	jmp    400812 <header+0x29>
  400804:	bf 3d 00 00 00       	mov    edi,0x3d
  400809:	e8 12 fd ff ff       	call   400520 <putchar@plt>
  40080e:	83 45 fc 01          	add    DWORD PTR [rbp-0x4],0x1
  400812:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  400815:	83 f8 14             	cmp    eax,0x14
  400818:	76 ea                	jbe    400804 <header+0x1b>
  40081a:	bf d6 09 40 00       	mov    edi,0x4009d6
  40081f:	e8 0c fd ff ff       	call   400530 <puts@plt>
  400824:	90                   	nop
  400825:	c9                   	leave  
  400826:	c3                   	ret    
```
拿到Address之後就可以使用GDB了，打開GDB先設斷點``b *0x00000000004007e9``，執行``r``，在call set_time之前，`` set $RIP=0x40084f``，這樣下一個指到的位址就不是set_time而是get_key，接下來就一直``ni``到flag出來就好了

## Git_Leak
利用[GitHack](https://github.com/lijiejie/GitHack)還原index.php，flag就在code裡。
```bash=
python GitHack.py ctf.hackersir.org:10022/.git
```

## 