# web
#owasp top 10 https://www.owasp.org/index.php/Top_10_2013
#漏洞測試
#滲透測試
#黑箱vs白箱測試(必考)
#WAF
2017 https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project
A1:2017-Injection
A2:2017-Broken Authentication
A3:2017-Sensitive Data Exposure
A4:2017-XML External Entities (XXE)
A5:2017-Broken Access Control
A6:2017-Security Misconfiguration
A7:2017-Cross-Site Scripting (XSS)
A8:2017-Insecure Deserialization
A9:2017-Using Components with Known Vulnerabilities
A10:2017-Insufficient Logging&Monitoring
A1：2017年，注射
A2：2017年破損認證
A3：2017年 - 敏感數據曝光
A4：2017-XML外部實體（XXE）
A5：2017年破損訪問控制
A6：2017-安全配置錯誤
A7：2017-Cross-Site Scripting（XSS）
A8：2017年 - 不安全的反序列化
A9：2017-使用已知漏洞的組件
A10：2017-記錄和監控不足
2013 https://www.owasp.org/index.php/Top_10_2013-Top_10

← 風險	
2013年目錄
2013年十大榜單

A1-注射 →

A1-注射
當不受信任的數據作為命令或查詢的一部分發送到解釋器時，會發生SQL，OS和LDAP注入等注入漏洞。攻擊者的惡意數據可能會欺騙解釋器執行非預期的命令或在沒有適當授權的情況下訪問數據。

A2-Broken認證和會話管理
與身份驗證和會話管理相關的應用程序功能通常無法正確實現，允許攻擊者破壞密碼，密鑰或會話令牌，或利用其他實現缺陷來假設其他用戶的身份。


A3-Cross-Site腳本（XSS）
只要應用程序獲取不受信任的數據並將其發送到Web瀏覽器而沒有正確的驗證或轉義，就會出現XSS漏洞。XSS允許攻擊者在受害者的瀏覽器中執行腳本，這些腳本可能會劫持用戶會話，破壞網站或將用戶重定向到惡意站點。


A4-不安全的直接對象參考
當開發人員公開對內部實現對象（如文件，目錄或數據庫鍵）的引用時，會發生直接對象引用。如果沒有訪問控制檢查或其他保護，攻擊者可以操縱這些引用來訪問未經授權的數據。


A5-安全配置錯誤
良好的安全性要求為應用程序，框架，應用程序服務器，Web服務器，數據庫服務器和平台定義和部署安全配置。應定義，實施和維護安全設置，因為默認設置通常不安全。此外，軟件應保持最新。


A6敏感數據暴露
許多Web應用程序無法正確保護敏感數據，例如信用卡，稅號和身份驗證憑據。攻擊者可能竊取或修改此類受到弱保護的數據，以進行信用卡欺詐，身份盜竊或其他犯罪行為。敏感數據需要額外的保護，例如靜止或傳輸時的加密，以及與瀏覽器交換時的特殊預防措施。


A7缺失功能級訪問控制
大多數Web應用程序在UI中顯示該功能之前驗證功能級別訪問權限。但是，應用程序需要在訪問每個函數時對服務器執行相同的訪問控制檢查。如果未驗證請求，攻擊者將能夠偽造請求，以便在未經適當授權的情況下訪問功能。


A8-跨站請求偽造（CSRF）
CSRF攻擊強制登錄受害者的瀏覽器向易受攻擊的Web應用程序發送偽造的HTTP請求，包括受害者的會話cookie和任何其他自動包含的身份驗證信息。這允許攻擊者強制受害者的瀏覽器生成易受攻擊的應用程序認為是來自受害者的合法請求的請求。

A9-使用已知漏洞的組件
組件（如庫，框架和其他軟件模塊）幾乎總是以完全權限運行。如果利用易受攻擊的組件，這種攻擊可能會導致嚴重的數據丟失或服務器接管。使用具有已知漏洞的組件的應用程序可能會破壞應用程序防禦並實現一系列可能的攻擊和影響。


A10-未經驗證的重定向和轉發
Web應用程序經常將用戶重定向並轉發到其他頁面和網站，並使用不受信任的數據來確定目標頁面。如果沒有經過適當的驗證，攻擊者可以將受害者重定向到網絡釣魚或惡意軟件站點，或者使用轉發來訪問未經授權的頁面。

← Risk	
2013 Table of Contents
2013 Top 10 List

A1-Injection →

A1-Injection
Injection flaws, such as SQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

A2-Broken Authentication and Session Management
Application functions related to authentication and session management are often not implemented correctly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities.


A3-Cross-Site Scripting (XSS)
XSS flaws occur whenever an application takes untrusted data and sends it to a web browser without proper validation or escaping. XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.


A4-Insecure Direct Object References
A direct object reference occurs when a developer exposes a reference to an internal implementation object, such as a file, directory, or database key. Without an access control check or other protection, attackers can manipulate these references to access unauthorized data.


A5-Security Misconfiguration
Good security requires having a secure configuration defined and deployed for the application, frameworks, application server, web server, database server, and platform. Secure settings should be defined, implemented, and maintained, as defaults are often insecure. Additionally, software should be kept up to date.


A6-Sensitive Data Exposure
Many web applications do not properly protect sensitive data, such as credit cards, tax IDs, and authentication credentials. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data deserves extra protection such as encryption at rest or in transit, as well as special precautions when exchanged with the browser.


A7-Missing Function Level Access Control
Most web applications verify function level access rights before making that functionality visible in the UI. However, applications need to perform the same access control checks on the server when each function is accessed. If requests are not verified, attackers will be able to forge requests in order to access functionality without proper authorization.


A8-Cross-Site Request Forgery (CSRF)
A CSRF attack forces a logged-on victim’s browser to send a forged HTTP request, including the victim’s session cookie and any other automatically included authentication information, to a vulnerable web application. This allows the attacker to force the victim’s browser to generate requests the vulnerable application thinks are legitimate requests from the victim.

A9-Using Components with Known Vulnerabilities
Components, such as libraries, frameworks, and other software modules, almost always run with full privileges. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications using components with known vulnerabilities may undermine application defenses and enable a range of possible attacks and impacts.


A10-Unvalidated Redirects and Forwards
Web applications frequently redirect and forward users to other pages and websites, and use untrusted data to determine the destination pages. Without proper validation, attackers can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.

