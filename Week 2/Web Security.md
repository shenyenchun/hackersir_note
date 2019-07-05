---
###### tags: `Hackersir note`
---
# Web Security

## OWASP
* Open Web Application Security Project (Foundation)
* 致力於促進網頁安全的非營利組織
* 提供網頁安全相關的技術文件、專案、工具、研討會
* [2017 OWASP Top 10](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)

## Tool
* BurpSuite
    * Proxy，可以攔截 Request & Response 封包
* Hackbar
    * FireFox套件
    * 鍵盤駭客
    * 小功能很多
    ![](https://i.imgur.com/ep8sk4a.png)

## Sensitive Data Exposure(A3:2017)

### 定義
敏感資訊指網站伺服器不願意讓別知道的任何訊息都算敏感資訊，E.g.網站備份檔案、網站後台相關頁面路徑、管理員帳號密碼、員工個資…etc

### 經驗解法

#### /robots.txt
許多網站會放這個檔案在根目錄底下，主要是告訴搜尋引擎的爬蟲可否爬這檔案內列出的資源，還有被禁止爬取的資源有可能包含敏感資訊

#### /.git/
* 專案版本控制
* 如果網站不小心公開 .git 目錄的話，攻擊者可以下載回來還原整包原始碼
* [GitHack](https://github.com/lijiejie/GitHack
)

#### 暫存檔名稱
* 開發者為求方便而產生的檔案
    * .tmp  test.php  xxx.php2  …
* 編輯器自動產生的備份檔案
    * index.php~  .index.php.swp  index.php.save  index.php.save2…
* Bash 命令歷史紀錄
    * .bash_history

#### 敏感名稱
* /admin  /phpmyadmin /login /backend /backup

### 掃描工具

#### Nmap
* 掃 port 的好夥伴，觀察目標有哪些服務開著，找有洞的打!也可以掃 IP 掃 OS
* CTF 不太會用到，但滲透測試一定用

#### dirsearch, dirBuster
* 自動化掃目錄工具，根據字典檔內容不斷嘗試，窮舉破解
* [dirsearch](https://github.com/maurosoria/dirsearch
)
:::danger
注意!! 屬於比較侵略型的掃描
CTF中，除非主辦方特別歡迎，否則還是少掃為妙
現實中有些網站會防止這種掃描，掃一下IP就被ban
:::

#### Sublist3r 
掃描 subdomain 的好夥伴
幫你從各大搜尋引擎尋找目標的subdomain
[Sublist3r](https://github.com/aboul3la/Sublist3r)

尋找防禦較薄弱的旁站來打，打進之後再想辦法打回主站!

#### Google Hacking

## Injection(A1:2017)
* 概念
應用程式 (直譯器) 將使用者的輸入誤判為非預期的程式碼或指令，並且執行。
e.g. SQL injection, OS Command injection, Cross-Site Scripting …etc
* 影響
攻擊者能執行非預期的指令或程式碼，進而有機會掌控應用程式、伺服器、瀏覽器(他人)。
### SQLi
* Structured Query Language
    * 結構化查詢語言
    * 應用於操作關聯式資料庫
    * 語法由單純的子句構成，簡單易學
* SQL Injection
    * 攻擊者在輸入字串中夾帶 SQL 指令
    * 程式若沒有對輸入做適當檢查，則會**將輸入誤判為合法 SQL 指令並執行**，對資料庫作相對應操作
* 危害
    * 攻擊者可以對資料庫做任意操作
    * 讀取、更新、新增、刪除資料庫內的資料
    * SELECT、UPDATE、INSERT、DELETE
* 結構
```sql=
SELECT * FROM Users WHERE name='Y.C_Shen';
```
method: SELECT
column: *
table: Users
指定column值: name
值:'Y.C_Shen'


#### 萬能密碼
![](https://i.imgur.com/6FvEIYf.png)
```
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```
Tip:
1. ``--``
2. ``#``
3. ``/**/``

如果``` $username=' or 1=1 #``` 
```
SELECT * FROM users WHERE username = '' or 1=1 #' AND password = '$password';
```
it work!

#### 基本防禦-過濾
過濾敏感字元:' " AND OR SELECT...etc，然後網頁就彈出警告，或網頁卡住
* 基本繞過方法:
    * ```/**/``` 在大多語言裡都代表註釋，在 MySQL 裡也是
    * MySQL 多實作了一種功能，在```/**/```裡加一個驚嘆號，那麼```/*!*/ ```裡的語句還是會被 MySQL 執行
    * 敏感字元用註釋起來，在前面加驚嘆號，這樣在其他語言看來是註解，但 MySQL 會執行
```
SELECT password FROM users WHERE account=‘’ /*!or*/ 1=1#’;   
```
因為過濾的程式以為``or``被註解掉了，所以忽略掉沒過濾到

### 進階SQLi
如果撈任意想要的資料，至少需要三樣東西:
    * 資料庫名 : schema_name
    * 表格名 : table_name
    * 欄位名 : column_name

* information_schema
    * information_schema 是內建的 database，包含了全部 database 的結構信息，E.g. database 名稱(schema_name)、table 名稱(table_name)、column 名稱(column_name)

* 撈資料三步驟
    * 找資料庫名 :
        ```
        SELECT schema_name FROM information_schema.schemata
        ```
    * 找表格名 :
        ```
        SELECT table_name FROM information_schema.tables WHERE table_schema=‘<資料庫名>’
        ```
    * 找欄位名 :
        ```
        SELECT column_name FROM information_schema.columns WHERE table_schema=‘<資料庫名>’ AND table_name=‘<表格名>’
        ```
    * 開始挖資料 :
        ```
        SELECT <欄位名> FROM <表格名>
        ```
### Union Based Injection
使用 UNION 將另一段 SELECT 指令串接在原來指令的後面
``
SELECT * FROM news WHERE id=1 UNION SELECT * FROM news WHERE id=2;
``
    * 語法限制
    UNION 前後兩個 SELECT 所選擇的 column 數量必須一致，否則語法錯誤
    ``SELECT  name,password FROM users WHERE name=‘Bob’ UNION SELECT id,name,password FROM users WHERE name=‘Alice’;``
        * 前面 name,password 與後面 id,name,password 的數量不一，所以語法錯誤
    ``SELECT  name,password FROM users WHERE name=‘Bob’ UNION SELECT email,phone FROM member 
WHERE name=‘Alice’;``
        * 前面 name,password 與後面 email,phone 的數量一樣，所以 work，即使查詢的 column_name 跟查詢的 table 不同也沒關係

### Order by
用於查詢共有幾個 column
```
SELECT * FROM users WHERE id = 1 order by 1      ---  WORK!
SELECT * FROM users WHERE id = 1 order by 2      ---  WORK!
SELECT * FROM users WHERE id = 1 order by 5      ---  FAIL!
SELECT * FROM users WHERE id = 1 order by 4      ---  WORK!
```
用 order by 慢慢逼近，就可以發現欄位為 4 個
### Blind SQL Injection
又稱 ”盲注”，基本上與一般的 SQL Injection 差不多，只是網站不會報錯，頂多回傳成功或失敗，因此難度提升很多
分兩種類型:
* Boolean Based
* Time Based

### Boolean Based
網站只會回彈查詢成功或失敗，沒有任何其他訊息

### Time Based
有些情況連成功或失敗都不會顯示，沒有任何訊息，這時候就可以使用 Time Based，用 SLEEP() 來判斷注入的語句是否成功，功的話就會因為 SLEEP() 的關係，網頁會延遲
e.g. ``id = 1 and SLEEP(10)``

### 利用 Blind SQL Injection 挖資料
先透過插入引號的方式判斷是否有注入漏洞``id = 1’``，如果顯示失敗，那很可能可以注入，一般情形的 SQL Injection 也可以先透過注入單引號的方式初步判斷是否有機會注入，如果網頁噴錯或是爛掉，那很可能有 SQL Injection 漏洞，然後做一連串逼近
* 發現可以注入後，可以先猜測資料庫名稱長度
```
1 and length(database())=1 #，顯示失敗；
1 and length(database())=2 #，顯示失敗；
1 and length(database())=3 #，顯示失敗；
1 and length(database())=4 #，顯示成功；
```
可以斷定當前資料庫的名稱長度為 4

``1 and ascii(substr(databse(),1,1))>97 #，顯示成功``
說明資料庫名第一個字的 ascii 碼大於 97 (a)
``1 and ascii(substr(databse(),1,1))<122 #，顯示成功``
說明資料庫名第一個字的 ascii 碼小於 122 (z)
``1 and ascii(substr(databse(),1,1))<103 #，顯示成功``
說明資料庫名第一個字的 ascii 碼小於 103 (g)
``1 and ascii(substr(databse(),1,1))<100 #，顯示失敗``
說明資料庫名第一個字的 ascii 碼不小於 100 (d)
``1 and ascii(substr(databse(),1,1))>100 #，顯示失敗``
說明資料庫名第一個字的 ascii 碼不大於 100 (d)

也就是說資料庫名的第一個字就是 d 了!!!

然後依此類推....

### OS Command Injection
* 從開發人員的角度出發
    ```php=
    system(“ping $_GET[‘ip’]”);
    ```
    想辦法串接下一個指令，用``;``閉合上一個指令，接著往下打新的指令
    ping 8.8.8.8; ls
    
    除了``;``可以閉合前一指令然後往下接新指令之外，還有很多招
    ``&& ls``
    ``|| ls``
    ``| ls``
    ``$(ls)``
    `` `ls` ``
* 有時候空白會被過濾掉，CTF 可以常看到一招解決上面問題的技巧``${IFS}``，IFS 是 shell 內建的一個變數，可以代表space、tab、newline，上面讀不到 flag 的問題就解決了!
e.g. ``cat${IFS}../../../flag``

## Broken Authentication(A2 : 2017)
* Cookie & Session
    伺服器可以將用戶的一些紀錄儲存在 Session，而每個 Session 對應到一個 SessionID，每個用戶會有一個唯一獨特的 SessionID ，儲存在瀏覽器 cookie 裡。如果 SessionID 不是隨機生成，就有機會猜出別的用戶 SessionID 長怎樣，進而冒用身分如果直接將認證資訊放在 cookie 裡而且沒有妥善加密，用戶就可以輕易竄改。
