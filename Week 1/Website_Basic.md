# Website Basic
## URL
完整版
[協定類型]://[存取資源需要的憑證資訊]@[伺服器位址]:[埠號]/[資源層級UNIX檔案路徑][檔名]?[查詢]#[片段ID]

標準版
[協定類型]://[伺服器位址]:[埠號]/[資源層級UNIX檔案路徑][檔名]?[查詢]#[片段ID]

[存取憑證資訊]、[埠號]、[查詢]、[片段ID]都屬於選填項

[查詢]：GET模式的表單參數，以「?」字元為起點，每個參數以「&」隔開，再以「=」分開參數名稱與資料，通常以UTF8的URL編碼，避開字元衝突的問題

[片段ID]：以「#」字元為起點

:::info
<scheme>://<netloc>/<path>?<query>#<fragment>
:::
Example:
https://fcu.edu.tw/iecs.php?page=index#hackersir
scheme: https        
netloc: fcu.edu.tw
path: iecs.php 
query: page=index
fragment: hackersir

## HTTP Protocal
用來表示我們Request的目的
* GET / POST / PUT / DELETE / OPTIONS ...
* GET
    * 跟伺服器要東西
    * 參數會出現在網址列
* POST
    * 送東西給伺服器
    * 參數不會出現在網址
    * 常用在登入、上傳檔案
### HTTP Protocol - Request
瀏覽器打 fcu.edu.tw，送出後的Request:
```
GET / HTTP/1.1
Host: fcu.edu.tw
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36
Gecko/20100101 Firefox/56.0
Accept:
text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-TW,zh;q=0.8,en-US;q=0.5,en;q=0.3
Connection: close
Upgrade-Insecure-Requests: 1
```
**GET**：HTTP Method (Verb)
**/**：Request Path 欲存取的資源位置
**HTTP/1.1**：HTTP Version 常見有1.0 / 1.1 / 2.0
**Host**：域名+Port(可選)
**User-Agent**：用來識別OS、瀏覽器版本等的特殊字串
### HTTP Protocol - GET
```
GET /news.php?id=100 HTTP/1.1
Host: fcu.edu.tw
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:56.0)
Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;
Connection: keep-alive
```
**?id=100**：GET Data

### HTTP Request - POST

```
POST /login.php HTTP/1.1
Host: fcu.edu.tw
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:56.0)
Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;
Connection: keep-alive

username=admin&password=asdasd //POST
```

### HTTP Protocol - Response
```
HTTP/1.1 200 OK
Date: Mon, 01 Oct 2018 05:48:12 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 23 May 2018 17:05:04 GMT
ETag: "69fe-56ce289380252"
Accept-Ranges: bytes
Content-Length: 27134
Vary: Accept-Encoding
Connection: close
Content-Type: text/plain
HERE IS CONTENT
```
**200**：Status Code 狀態代碼

### Status Code
Server處理完回傳的狀態代碼
* 1xx 有收到請求，但仍要繼續處理
* 2xx 成功，好棒棒
* 3xx 重導向相關的訊息
* 4xx Client端發生錯誤
* 5xx Server端發生錯誤

## Cookie
* 網站為了記錄資料，而在Client存放的小檔案
* 通常拿來紀錄帳號資訊
    * session id
    * 使用者是否登入
* HTTP是無狀態的 (stateless)
    * 透過Cookie追蹤使用者
    
## Information Leak
* 現實常見
* CTF不會直接sourse code，會藏一下
    * robots.txt
    * .git/.svn
    * .DS_Store
    * .index.php.swp
    * index.php~
    
### robots.txt
* 告訴搜尋引擎，哪些地方可以被檢索，哪些地方不能
* 有時可以找到一些難猜到的目錄、檔案
* CTF老梗

### .git/.svn
* 版本管理系統
* 常見線上部署環境忘記砍掉
* 可以還原Source Code

### .DS_Store
* Apple系統上常見的隱藏檔
* 能洩漏目錄資訊，如資料夾文件清單等
* [原理分析](https://0day.work/parsing-the-ds_store-file-format/)

### 其它Leak Source的套路
* Local File Inclusion (LFI)
* 任意檔案下載
* rsync
* ...

### Google Hacking
輔助滲透測試
* site:
    * 指定特定網站
* intext:
    * 搜索網頁正文出現的字串
* intitle:
    * 搜索網頁標題
* filetype: / ext:
    * 搜索特定類型副檔名
* [GHDB](https://www.exploit-db.com/google-hacking-database)

## 同源政策(Same Origin Policy)
* 瀏覽器的安全策略之一
* 不同域的客戶端腳本在沒授權的狀況下，無法讀取對方的資源
* 同域要求同協議、同域名、同端口
* 沒有這個規則，Web世界就毀滅惹
    * 例如: A網站可以任意存取B網站的Cookie
* 比較： http://www.fcu.edu.tw

| 站點 | 同域? | 原因 |
| :--------: | :--------: | :--------: |
| https://www.fcu.edu.tw | NO | 協議不同 |
| https://mmm.fcu.edu.tw | NO | 域名不同 |
| https://fcu.edu.tw | NO | 域名不同 |
| http://www.fcu.edu.tw:9999 | NO | Port不同 |
| http://www.fcu.edu.tw/iesc | YES | 同協議/同域名/同端口 |

### 跨域
* script,img,iframe 
    * 預設可以跨域請求資源
    * JSONP就是透過script可以跨域的特性來載入資源
* CORS (Cross-Origin Resource Sharing)
    * 添加一些HTTP Header來標示跨域請求
    * 可以分成「簡單請求」和「非簡單請求」
    * 簡單請求必須是HEAD/GET/POST方法，且Header有一定限制
    * 兩種請求的處理是不同的
    * [詳細](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/CORS)
    