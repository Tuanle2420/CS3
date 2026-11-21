# Playbook điều tra sự cố: Web, Jump, Mail, DC, VPN + Splunk


## 0. Cách dùng playbook

Điều tra theo 6 giai đoạn, không đi lần lượt từng máy; mỗi chỉ dấu tìm được (IP, user, file, host) được tìm lại trên mọi nguồn log để nối các máy thành một chuỗi.

1. **Khoanh vùng:** log nào có, máy nào bất thường, từ khi nào.
2. **Điểm vào:** Web, Mail, VPN (3 máy tiếp xúc Internet).
3. **Pivot IOC:** lấy chỉ dấu mới, tìm trên mọi index.
4. **Di chuyển nội bộ:** Web/VPN/Mail → Jump → DC.
5. **Hành động cuối:** leo quyền, persistence, exfil, xóa log.
6. **Hợp nhất và viết báo cáo:** timeline, ma trận ảnh hưởng, IOC, MITRE, đề xuất.

**Ký hiệu trong tài liệu:**

- **\[SPLUNK\]** – chạy trong Splunk Search. Tên index/field là ví dụ; mở một event mẫu, xem *Interesting fields* rồi sửa cho khớp lab.
- **\[HOST\]** – phải đăng nhập thẳng vào máy chủ (RDP/SSH/console) khi log Splunk thiếu, bị xóa, hoặc cần xác minh file/tiến trình/cấu hình. Ghi lại lệnh và kết quả để đưa vào báo cáo.

**Khi nào cần vào máy chủ:** log bị xóa (1102); cần lấy hash/nội dung webshell hoặc malware; cần kiểm tra tiến trình, kết nối mạng, scheduled task, service đang chạy; cần cấu hình Exchange/AD hiện tại; Splunk không thu loại log đó (IIS chi tiết, HttpProxy Exchange, bash history).

**Nguyên tắc khi vào máy chủ:** không xóa, không sửa, không tắt máy; lấy hash trước khi động vào file; ghi giờ hệ thống (`Get-Date`, `date -u`) để đối chiếu múi giờ với Splunk.

**Bảng ghi chú phát hiện** (mở song song suốt bài, mỗi dòng là một phát hiện F1, F2…):

| ID | Thời gian | Host | Phát hiện | IOC | Bằng chứng (query/lệnh) | Dẫn tới |
| --- | --- | --- | --- | --- | --- | --- |
| F1 |  |  |  |  |  |  |
| F2 |  |  |  |  |  |  |
| F3 |  |  |  |  |  |  |

Sau mỗi máy, tự hỏi hai câu: **kẻ tấn công vào máy này từ đâu?** và **từ máy này đi tiếp tới đâu?**

## 1. Giai đoạn 1 – Khoanh vùng

Mục tiêu: biết có những log nào, của máy nào, khoảng thời gian nào, và bất thường bắt đầu từ đâu. Đặt Time range = **All time**.

**\[SPLUNK\] Danh sách nguồn dữ liệu**

```
| tstats count min(_time) as first max(_time) as last where index=* by index, sourcetype, host
| convert ctime(first) ctime(last)
```

**\[SPLUNK\] Mật độ log theo thời gian và theo máy** (đỉnh bất thường đầu tiên thường gần điểm vào)

```
index=* | timechart span=1h count by host
```

**\[SPLUNK\] Đếm Event ID quan trọng theo máy**

```
index=wineventlog EventCode IN (4625,4624,4648,4672,4720,4728,4732,4756,4769,4662,5136,4698,7045,1102)
| stats count by host, EventCode | sort host, EventCode
```

**\[SPLUNK\] Các field có trong mỗi sourcetype** (để viết query đúng tên field)

```
index=<tên_index> | head 1000 | fieldsummary | table field count distinct_count values
```

**\[HOST\] Giờ hệ thống và múi giờ** (Windows / Linux)

```
Get-Date; Get-TimeZone
date -u; timedatectl
```

Kết quả cần ghi vào báo cáo: danh sách index/sourcetype/host, khoảng thời gian dữ liệu, múi giờ dùng trong báo cáo, các máy có Event ID nghiêm trọng (1102, 4720, 4728, 7045).

## 2. Giai đoạn 2a – Web server

Câu hỏi cần trả lời: IP nào dò quét, khai thác lỗi gì, có thành công không (status 200, response lớn), có webshell không, webshell đã chạy lệnh gì.

| Dấu hiệu | Ý nghĩa |
| --- | --- |
| Một IP, hàng trăm URI khác nhau, nhiều 404 | Dò quét thư mục (gobuster, dirb) |
| UA sqlmap, nikto, wpscan, Nmap | Công cụ tấn công tự động |
| `union select`, `' or 1=1`, `sleep(` trong URI | SQL Injection |
| `../`, `/etc/passwd`, `win.ini` | LFI / Path traversal |
| POST tới trang upload, sau đó GET/POST tới file .php/.aspx/.jsp lạ | Upload webshell |
| w3wp.exe / httpd / php-fpm sinh ra cmd, powershell, sh | Webshell đang chạy lệnh |

**\[SPLUNK\] Top IP và User-Agent**

```
index=web | stats count dc(uri) as uniq_uri values(status) as status by clientip, useragent | sort -count
```

**\[SPLUNK\] Công cụ quét**

```
index=web (useragent="*sqlmap*" OR useragent="*nikto*" OR useragent="*gobuster*" OR useragent="*wpscan*" OR useragent="*Nmap*" OR useragent="*dirbuster*")
| stats count min(_time) as first by clientip, useragent | convert ctime(first)
```

**\[SPLUNK\] Payload khai thác**

```
index=web (uri="*union*select*" OR uri="*or%201=1*" OR uri="*sleep(*" OR uri="*../..*" OR uri="*etc/passwd*" OR uri="*cmd=*" OR uri="*whoami*" OR uri="*<script*")
| table _time clientip method uri status bytes
```

**\[SPLUNK\] Khai thác thành công?** (cùng IP, status 200, kích thước lớn bất thường)

```
index=web clientip=<IP_attacker> status=200 | stats count avg(bytes) max(bytes) by uri | sort -max(bytes)
```

**\[SPLUNK\] Upload và webshell**

```
index=web method=POST (uri="*upload*" OR uri="*.php*" OR uri="*.aspx*" OR uri="*.jsp*")
| stats count min(_time) as first by clientip, uri | sort first | convert ctime(first)
```

File nào ít người truy cập, chỉ một IP gọi, và xuất hiện sau request upload thì nghi là webshell.

**\[SPLUNK\] Tiến trình web sinh shell** (Sysmon 1 / 4688)

```
index=* (EventCode=1 OR EventCode=4688) (ParentImage="*w3wp.exe" OR ParentImage="*httpd*" OR ParentImage="*php*" OR ParentImage="*tomcat*")
| table _time host ParentImage Image CommandLine
```

**\[SPLUNK\] File script mới trong webroot** (Sysmon 11)

```
index=sysmon EventCode=11 (TargetFilename="*inetpub*" OR TargetFilename="*www*") (TargetFilename="*.aspx" OR TargetFilename="*.php" OR TargetFilename="*.jsp")
| table _time host Image TargetFilename
```

**\[HOST\] Windows/IIS – xác minh webshell**

```
# File script mới sửa trong 7 ngày
Get-ChildItem C:\inetpub -Recurse -Include *.aspx,*.ashx,*.asp,*.php -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select FullName, LastWriteTime, Length

# Hash và nội dung file nghi ngờ
Get-FileHash C:\inetpub\wwwroot\uploads\shell.aspx -Algorithm SHA256
Get-Content C:\inetpub\wwwroot\uploads\shell.aspx | Select -First 40

# Tìm chuỗi đặc trưng webshell
Select-String -Path C:\inetpub\wwwroot\* -Pattern 'eval\(|Process.Start|cmd.exe|FromBase64String' -Recurse

# IIS log gốc (khi Splunk thiếu)
Get-ChildItem C:\inetpub\logs\LogFiles\W3SVC1 | Sort LastWriteTime | Select -Last 3
Select-String -Path C:\inetpub\logs\LogFiles\W3SVC1\*.log -Pattern 'shell.aspx'
```

**\[HOST\] Linux/Apache/Nginx – xác minh webshell**

```
find /var/www -type f \( -name '*.php' -o -name '*.jsp' \) -mtime -7 -ls
grep -RniE 'eval\(|base64_decode|system\(|shell_exec|passthru' /var/www
sha256sum /var/www/html/uploads/shell.php
grep '<IP_attacker>' /var/log/apache2/access.log /var/log/nginx/access.log
ps -ef --forest | grep -E 'www-data|apache|nginx'
ss -antp | grep ESTAB
cat /var/www/.bash_history 2>/dev/null; crontab -u www-data -l
```

**\[HOST\] Thông tin bị lộ nếu SQLi thành công:** mở file cấu hình (`web.config`, `config.php`, `.env`) để biết tài khoản DB bị lộ; bảng users có thể là nguồn của password spray vào Mail/VPN sau đó.

## 3. Giai đoạn 2b – Mail server

Câu hỏi cần trả lời: có phishing không và ai đã mở; có password spray / mailbox bị chiếm không; có khai thác CVE không (CVE nào, bằng chứng gì); attacker đã làm gì trên mail server.

### 3.1 Phishing

**\[SPLUNK\] File đính kèm nguy hiểm và người gửi lạ**

```
index=mail (attachment="*.docm" OR attachment="*.xlsm" OR attachment="*.zip" OR attachment="*.iso" OR attachment="*.lnk" OR attachment="*.hta" OR attachment="*.exe")
| table _time sender recipient subject attachment src_ip
index=mail | stats count dc(recipient) as nguoi_nhan by sender, subject | sort count
```

**\[SPLUNK\] Ai đã mở file?** (Office sinh tiến trình con)

```
index=* EventCode=1 ParentImage IN ("*WINWORD.EXE","*EXCEL.EXE","*OUTLOOK.EXE","*POWERPNT.EXE") Image IN ("*powershell.exe","*cmd.exe","*mshta.exe","*rundll32.exe","*regsvr32.exe","*wscript.exe")
| table _time host user ParentImage Image CommandLine
```

### 3.2 Password spray / chiếm mailbox

```
index=mail (action=failure OR status=401) | stats dc(user) as so_user count by src_ip | where so_user>10
index=mail action=success src_ip=<IP_spray> | table _time user src_ip
index=* ("New-InboxRule" OR "Set-InboxRule" OR "ForwardingSmtpAddress" OR "RedirectTo") | table _time host user _raw
```

### 3.3 Khai thác CVE trên Exchange

| CVE | Chữ ký trong IIS log | Xác thực |
| --- | --- | --- |
| ProxyLogon (CVE-2021-26855, 27065, 26857, 26858) | `/ecp/*.js` (file không tồn tại), cookie `X-BEResource` / `X-AnonResource-Backend`, `/ecp/DDI/DDIService.svc/SetObject`, `proxyLogon.ecp` | Không |
| ProxyShell (CVE-2021-34473, 34523, 31207) | `/autodiscover/autodiscover.json?@...` tới `/mapi/` hoặc `/powershell/`, tham số `X-Rps-CAT` | Không (cs\_username = -) |
| ProxyNotShell (CVE-2022-41040, 41082) | Cùng mẫu `autodiscover.json?@...powershell` | **Có** (cs\_username có giá trị) |

**\[SPLUNK\] Phát hiện ProxyLogon**

```
index=iis host=MAIL* (cs_uri_stem="/ecp/*.js" OR cs_uri_stem="*proxyLogon.ecp*" OR cs_uri_stem="*DDIService.svc*")
| table _time c_ip cs_method cs_uri_stem sc_status cs_User_Agent
```

**\[SPLUNK\] Phân biệt ProxyShell / ProxyNotShell**

```
index=iis host=MAIL* cs_uri_stem="*autodiscover.json*" (cs_uri_query="*@*" OR cs_uri_query="*powershell*" OR cs_uri_query="*X-Rps-CAT*")
| eval loai=if(cs_username="-" OR isnull(cs_username), "ProxyShell (không xác thực)", "ProxyNotShell (có user)")
| stats count min(_time) as first by c_ip, cs_username, loai | convert ctime(first)
```

**\[SPLUNK\] Lạm dụng lệnh Exchange** (log MSExchange Management)

```
index=* host=MAIL* ("New-ManagementRoleAssignment" OR "New-MailboxExportRequest" OR "Set-OabVirtualDirectory" OR "New-InboxRule")
| table _time host user _raw
```

**\[SPLUNK\] Webshell và lệnh chạy qua webshell**

```
index=sysmon host=MAIL* EventCode=11 (TargetFilename="*\\aspnet_client\\*.aspx" OR TargetFilename="*\\owa\\auth\\*.aspx" OR TargetFilename="*\\ecp\\auth\\*.aspx")
| table _time Image TargetFilename
index=sysmon host=MAIL* EventCode=1 ParentImage IN ("*w3wp.exe","*UMWorkerProcess.exe","*UMService.exe") Image IN ("*cmd.exe","*powershell.exe","*certutil.exe","*rundll32.exe")
| table _time ParentImage Image CommandLine
```

**\[HOST\] Exchange Management Shell – xác minh trực tiếp**

```
# Phiên bản Exchange (đối chiếu bản vá)
Get-ExchangeServer | fl Name, AdminDisplayVersion

# Export mailbox bất thường (ProxyShell ghi webshell bằng cách này)
Get-MailboxExportRequest | fl Mailbox, FilePath, Status, WhenCreated

# Ai được gán quyền Mailbox Import Export
Get-ManagementRoleAssignment -Role "Mailbox Import Export" | fl RoleAssignee, WhenCreated

# ProxyLogon CVE-2021-27065: ExternalUrl chứa <script>
Get-OabVirtualDirectory | fl Server, ExternalUrl, InternalUrl

# Rule chuyển tiếp thư trên mailbox bị chiếm
Get-InboxRule -Mailbox hr.lan | fl Name, ForwardTo, RedirectTo, DeleteMessage
Get-Mailbox -ResultSize Unlimited | ? {$_.ForwardingSmtpAddress} | fl Name, ForwardingSmtpAddress

# Truy vết thư phishing / thư gửi ra
Get-MessageTrackingLog -Start (Get-Date).AddDays(-7) -Sender attacker@c0mpany.com | ft Timestamp, Recipients, MessageSubject

# Log quản trị Exchange
Get-WinEvent -LogName 'MSExchange Management' | ? {$_.Message -match 'New-MailboxExportRequest|New-ManagementRoleAssignment|Set-OabVirtualDirectory'} | fl TimeCreated, Message
```

**\[HOST\] HttpProxy log của Exchange** (nguồn mạnh nhất cho ProxyLogon, thường không có trong Splunk)

```
# Request SSRF: AuthenticatedUser rỗng, AnchorMailbox dạng ServerInfo~*/*
Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:ExchangeInstallPath\Logging\HttpProxy" -Filter '*.log').FullName |
  ? { $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, ClientIpAddress, UrlStem, AnchorMailbox

# Webshell trong thư mục Exchange/IIS
Get-ChildItem -Recurse -Include *.aspx -Path C:\inetpub\wwwroot\aspnet_client, "$env:ExchangeInstallPath\FrontEnd\HttpProxy\owa\auth" |
  sort LastWriteTime -Descending | select FullName, LastWriteTime, Length
Get-FileHash <đường_dẫn_webshell> -Algorithm SHA256

# File dump LSASS thường để lại
Get-ChildItem C:\ -Recurse -Include *.dmp -ErrorAction SilentlyContinue | select FullName, LastWriteTime
```

Có thể chạy script chính thức `Test-ProxyLogon.ps1` của Microsoft (CSS-Exchange) nếu lab cho phép.

### 3.4 Zimbra (nếu mail chạy Linux) – CVE-2022-41352

Email đính kèm `.cpio` / `.tar` độc; amavis giải nén và ghi file JSP vào webroot; attacker gọi `/public/*.jsp`.

```
index=mail attachment IN ("*.cpio","*.tar","*.rpm") | table _time sender recipient attachment
index=web host=MAIL* uri="/public/*.jsp*" | table _time clientip uri status
```

**\[HOST\] Zimbra**

```
find /opt/zimbra/jetty*/webapps -name '*.jsp' -mtime -14 -ls
grep -i 'cpio' /var/log/zimbra.log | tail -50
su - zimbra -c 'zmcontrol -v'
ps -ef --forest | grep zimbra; ss -antp | grep ESTAB
```

## 4. Giai đoạn 2c – VPN

Câu hỏi cần trả lời: tài khoản nào bị dò/chiếm, đăng nhập từ IP/quốc gia nào, lúc nào, được cấp **IP nội bộ** nào (IP này dùng để truy vết sang Jump/DC).

**\[SPLUNK\] Brute force rồi thành công**

```
index=vpn | stats count(eval(action="failure")) as fail count(eval(action="success")) as ok by user, src_ip
| where fail>10 AND ok>0 | sort -fail
```

**\[SPLUNK\] Password spray** (một IP, nhiều user)

```
index=vpn action=failure | stats dc(user) as so_user count by src_ip | where so_user>10
```

**\[SPLUNK\] Quốc gia lạ / impossible travel**

```
index=vpn action=success | iplocation src_ip
| stats values(Country) as quoc_gia dc(Country) as n min(_time) as first by user | where n>1 | convert ctime(first)
```

**\[SPLUNK\] Đăng nhập ngoài giờ**

```
index=vpn action=success | eval gio=tonumber(strftime(_time,"%H")) | where gio<6 OR gio>22
| table _time user src_ip assigned_ip
```

**\[SPLUNK\] IP nội bộ được cấp và nơi nó kết nối tới**

```
index=vpn user=<user_bi_chiem> action=success | table _time user src_ip assigned_ip session_id
index=* (src_ip=<assigned_ip> OR Source_Network_Address=<assigned_ip> OR src=<assigned_ip>) | stats count by index, host, dest_port
```

**\[HOST\] Trên thiết bị VPN** (tùy hãng, ví dụ)

```
# FortiGate
execute log filter category event
execute log filter field subtype vpn
execute log display
get vpn ssl monitor

# OpenVPN (Linux)
grep -E 'AUTH_FAILED|Peer Connection Initiated' /var/log/openvpn*.log
cat /etc/openvpn/openvpn-status.log

# Windows RRAS / NPS
Get-WinEvent -LogName Security | ? {$_.Id -in 6272,6273} | select TimeCreated, Message -First 50
```

Nếu thiết bị VPN có lỗ hổng đã biết (Fortinet, Pulse/Ivanti, Citrix…), kiểm tra phiên bản firmware và request lạ tới giao diện web của thiết bị trong log.

## 5. Giai đoạn 3 – Pivot IOC chéo nguồn

Mỗi IOC mới (IP, user, file, hash, domain) đều được tìm trên **toàn bộ** index để thấy nó xuất hiện ở đâu, lần đầu lúc nào.

**\[SPLUNK\] Một IOC xuất hiện ở những đâu**

```
index=* "<IOC>" | stats count min(_time) as first max(_time) as last by index, sourcetype, host
| convert ctime(first) ctime(last) | sort first
```

**\[SPLUNK\] IP bên ngoài xuất hiện ở nhiều nguồn** (dấu hiệu mạnh nhất của cùng một attacker)

```
index=web OR index=mail OR index=vpn OR index=iis OR index=firewall
| eval ip=coalesce(clientip, c_ip, src_ip, src)
| where NOT cidrmatch("10.0.0.0/8", ip) AND NOT cidrmatch("172.16.0.0/12", ip) AND NOT cidrmatch("192.168.0.0/16", ip)
| stats dc(index) as so_nguon values(index) as nguon min(_time) as first by ip | where so_nguon>1
| convert ctime(first) | sort first
```

**\[SPLUNK\] Một user hoạt động ở những máy nào**

```
index=* (user="<user>" OR Account_Name="<user>" OR TargetUserName="<user>")
| stats count min(_time) as first by index, host, EventCode | convert ctime(first) | sort first
```

**\[SPLUNK\] Timeline gộp nhiều IOC**

```
index=* ("<IP1>" OR "<user1>" OR "<file1>" OR "<domain1>")
| eval nguon=index.":".host | table _time nguon EventCode user src_ip dest uri CommandLine | sort _time
```

**\[HOST\] Khi cần hash để tra cứu:** `Get-FileHash <file> -Algorithm SHA256` (Windows) hoặc `sha256sum <file>` (Linux), rồi tìm hash đó trên Splunk (Sysmon 1 có field Hashes) để biết file đã chạy trên những máy nào.

```
index=sysmon EventCode=1 Hashes="*<SHA256>*" | stats count min(_time) as first by host, Image | convert ctime(first)
```

## 6. Giai đoạn 4 – Jump server và di chuyển nội bộ

Câu hỏi cần trả lời: ai vào Jump từ đâu; có dump credential không, lấy được tài khoản nào; từ Jump đi tiếp tới máy nào; có cài persistence không.

| Logon Type (4624) | Ý nghĩa |
| --- | --- |
| 2 | Đăng nhập tại chỗ (console) |
| 3 | Qua mạng (SMB, PsExec, WMI, truy cập share) |
| 9 | NewCredentials (runas /netonly, thường thấy khi pass-the-hash) |
| 10 | RDP |

**\[SPLUNK\] Brute force RDP**

```
index=wineventlog host=JUMP* EventCode=4625 | stats count by Source_Network_Address, user | sort -count
index=wineventlog host=JUMP* EventCode=4624 Logon_Type=10 | table _time user Source_Network_Address
```

**\[SPLUNK\] Ai vào máy nào** (bản đồ lateral movement cho toàn hệ thống)

```
index=wineventlog EventCode=4624 Logon_Type IN (3,9,10) NOT user="*$" NOT user="ANONYMOUS LOGON"
| stats count min(_time) as first values(user) as users by Source_Network_Address, host, Logon_Type
| convert ctime(first) | sort first
```

**\[SPLUNK\] Dump credential**

```
index=sysmon EventCode=10 TargetImage="*lsass.exe" NOT SourceImage IN ("*MsMpEng.exe","*svchost.exe","*wininit.exe")
| table _time host SourceImage GrantedAccess
index=* (CommandLine="*sekurlsa*" OR CommandLine="*lsadump*" OR CommandLine="*procdump*lsass*" OR CommandLine="*comsvcs*MiniDump*" OR CommandLine="*reg save*hklm\\sam*" OR CommandLine="*reg save*hklm\\system*")
| table _time host user CommandLine
```

**\[SPLUNK\] Công cụ lateral movement**

```
index=wineventlog EventCode=7045 | table _time host Service_Name Service_File_Name
index=wineventlog EventCode=4648 | table _time host user Target_Server_Name Process_Name
index=sysmon EventCode=1 (Image="*psexec*" OR Image="*wmic.exe" OR CommandLine="*Invoke-Command*" OR CommandLine="*Enter-PSSession*" OR ParentImage="*WmiPrvSE.exe")
| table _time host user ParentImage Image CommandLine
```

**\[SPLUNK\] Persistence**

```
index=wineventlog EventCode IN (4698,4720,4732,7045) | table _time host EventCode user _raw
index=sysmon EventCode=13 TargetObject IN ("*\\CurrentVersion\\Run*","*\\Services\\*\\ImagePath") | table _time host Image TargetObject Details
```

**\[SPLUNK\] PowerShell bị mã hóa / tải file**

```
index=* (EventCode=4104 OR EventCode=1) (CommandLine="*-enc*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*" OR CommandLine="*certutil*-urlcache*" OR ScriptBlockText="*Invoke-Mimikatz*")
| table _time host user CommandLine ScriptBlockText
```

Giải mã chuỗi sau `-enc`: CyberChef → From Base64 → Decode text (UTF-16LE).

**\[HOST\] Live response Windows** (Jump, hoặc bất kỳ máy Windows nào bị nghi)

```
# Phiên đăng nhập hiện tại
quser; qwinsta

# Tiến trình kèm dòng lệnh và tiến trình cha
Get-CimInstance Win32_Process | select ProcessId, ParentProcessId, Name, CommandLine | ft -AutoSize -Wrap

# Kết nối mạng đang mở kèm tiến trình
Get-NetTCPConnection -State Established | select LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
  @{n='Process';e={(Get-Process -Id $_.OwningProcess).Name}}

# Persistence
Get-ScheduledTask | ? {$_.Date -gt (Get-Date).AddDays(-7) -or $_.TaskPath -notlike '\Microsoft*'} | select TaskName, TaskPath, Date, @{n='Action';e={$_.Actions.Execute}}
Get-CimInstance Win32_Service | ? {$_.PathName -notlike '*Windows*'} | select Name, State, StartMode, PathName
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Get-LocalUser | select Name, Enabled, LastLogon; Get-LocalGroupMember Administrators

# Tool attacker thường để lại
Get-ChildItem C:\Users\*\Downloads, C:\Users\*\AppData\Local\Temp, C:\Windows\Temp, C:\ProgramData, C:\Users\Public -Recurse -Include *.exe,*.ps1,*.dmp,*.zip,*.7z -ErrorAction SilentlyContinue |
  ? {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | select FullName, LastWriteTime, Length

# Lịch sử lệnh PowerShell của từng user
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt | % { "== $_"; Get-Content $_ }

# RDP đã kết nối đi đâu (từ Jump sang máy khác)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers"
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RDPClient/Operational' -MaxEvents 50 | select TimeCreated, Message

# RDP vào máy này từ đâu (kể cả khi Security log bị xóa)
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | ? {$_.Id -in 21,24,25} | select TimeCreated, Id, Message -First 50

# Security log trực tiếp
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4720,4732,1102} -MaxEvents 200 | select TimeCreated, Id, Message

# Dấu vết thực thi chương trình
Get-ChildItem C:\Windows\Prefetch | sort LastWriteTime -Descending | select -First 40 Name, LastWriteTime
```

## 7. Giai đoạn 5 – Domain Controller

Câu hỏi cần trả lời: attacker đã lên Domain Admin chưa, bằng cách nào; có tài khoản/nhóm/GPO/ACL nào bị tạo hoặc sửa; có lấy toàn bộ hash domain không (DCSync, NTDS.dit); có xóa log không.

| Tấn công | Event ID / dấu hiệu |
| --- | --- |
| Kerberoasting | 4769, `Ticket_Encryption_Type=0x17` (RC4), một user xin TGS cho nhiều SPN |
| AS-REP Roasting | 4768, `Pre_Authentication_Type=0` |
| Password spray domain | 4771 (Kerberos), 4776 (NTLM), 4625 từ một nguồn cho nhiều user |
| DCSync | 4662, GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` / `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` / `89e95b76-444d-4c62-991a-0facbeda640c`, do tài khoản không phải DC |
| Cấp quyền DCSync | 5136 sửa `nTSecurityDescriptor` trên object domainDNS |
| Dump NTDS.dit | `ntdsutil ... ifm`, `vssadmin create shadow`, copy `ntds.dit` + `SYSTEM` |
| Tạo / leo quyền admin | 4720, 4722, 4728/4732/4756, 4672 |
| Sửa GPO | 5136 / 5137 trên `groupPolicyContainer`, file mới trong SYSVOL |
| Golden Ticket | 4769 không có 4768 trước đó, tên domain lạ trong 4624/4672 |
| Xóa dấu vết | 1102 (Security), 104 (System) |

**\[SPLUNK\] Kerberoasting**

```
index=wineventlog host=DC* EventCode=4769 Ticket_Encryption_Type=0x17 NOT Service_Name="*$" NOT Service_Name=krbtgt
| stats dc(Service_Name) as so_spn values(Service_Name) as spn by Account_Name, Client_Address | where so_spn>2
```

**\[SPLUNK\] AS-REP Roasting**

```
index=wineventlog host=DC* EventCode=4768 Pre_Authentication_Type=0 | table _time Account_Name Client_Address
```

**\[SPLUNK\] Password spray lên domain**

```
index=wineventlog host=DC* EventCode IN (4771,4776,4625)
| stats dc(Account_Name) as so_user count by Client_Address, EventCode | where so_user>10
```

**\[SPLUNK\] Tạo user và thêm vào nhóm đặc quyền**

```
index=wineventlog host=DC* EventCode IN (4720,4722,4724,4728,4732,4756)
| table _time EventCode Subject_Account_Name Target_Account_Name Group_Name Member_Name
```

**\[SPLUNK\] DCSync và cấp quyền DCSync**

```
index=wineventlog host=DC* EventCode=4662 (Properties="*1131f6aa*" OR Properties="*1131f6ad*" OR Properties="*89e95b76*") NOT Account_Name="*$"
| table _time Account_Name Properties
index=wineventlog host=DC* EventCode=5136 (ObjectClass=domainDNS OR AttributeLDAPDisplayName=nTSecurityDescriptor)
| table _time SubjectUserName ObjectDN AttributeLDAPDisplayName AttributeValue
```

Lưu ý: tài khoản máy DC (`DC01$`) replication là bình thường. Tài khoản user, hoặc tài khoản máy Exchange/Jump làm việc này là DCSync. Kiểm tra thêm 4624 cùng Logon\_ID để lấy IP nguồn.

**\[SPLUNK\] Dump NTDS.dit**

```
index=* host=DC* (CommandLine="*ntdsutil*" OR CommandLine="*vssadmin*create*shadow*" OR CommandLine="*ntds.dit*" OR CommandLine="*HarddiskVolumeShadowCopy*" OR CommandLine="*diskshadow*")
| table _time host user CommandLine
```

**\[SPLUNK\] Sửa GPO**

```
index=wineventlog host=DC* EventCode IN (5136,5137) ObjectClass=groupPolicyContainer
| table _time SubjectUserName ObjectDN AttributeLDAPDisplayName AttributeValue
index=sysmon host=DC* EventCode=11 TargetFilename="*SYSVOL*" (TargetFilename="*.ps1" OR TargetFilename="*.bat" OR TargetFilename="*.exe" OR TargetFilename="*ScheduledTasks.xml")
| table _time Image TargetFilename
```

**\[SPLUNK\] Golden Ticket** (TGS không có TGT tương ứng)

```
index=wineventlog host=DC* EventCode IN (4768,4769)
| eval acc=lower(mvindex(split(Account_Name,"@"),0))
| stats values(EventCode) as ev min(_time) as first by acc, Client_Address
| where mvcount(ev)=1 AND ev=4769 | convert ctime(first)
```

**\[SPLUNK\] Xóa log**

```
index=wineventlog EventCode IN (1102,104) | table _time host user _raw
```

**\[HOST\] PowerShell Active Directory trên DC**

```
Import-Module ActiveDirectory
$d = (Get-Date).AddDays(-7)

# User / nhóm mới tạo hoặc vừa sửa
Get-ADUser -Filter {whenCreated -gt $d} -Properties whenCreated, memberOf | select Name, SamAccountName, whenCreated, memberOf
Get-ADObject -Filter {whenChanged -gt $d} -Properties whenChanged | sort whenChanged -Descending | select Name, ObjectClass, whenChanged -First 50

# Thành viên nhóm đặc quyền
'Domain Admins','Enterprise Admins','Administrators','Schema Admins','Account Operators','Backup Operators' |
  % { "== $_"; Get-ADGroupMember $_ -Recursive | select SamAccountName, objectClass }

# Thời điểm thêm thành viên vào Domain Admins (kể cả khi log bị xóa)
repadmin /showobjmeta DC01 "CN=Domain Admins,CN=Users,DC=corp,DC=local"

# Tài khoản dễ bị Kerberoast / AS-REP roast
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName, PasswordLastSet | select SamAccountName, ServicePrincipalName, PasswordLastSet
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | select SamAccountName

# Ai có quyền replication (DCSync) trên domain
(Get-Acl "AD:\DC=corp,DC=local").Access | ? { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c' } |
  select IdentityReference, ActiveDirectoryRights, ObjectType

# AdminSDHolder bị sửa (persistence)
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=corp,DC=local").Access | select IdentityReference, ActiveDirectoryRights | sort IdentityReference -Unique

# GPO vừa sửa và nội dung SYSVOL
Get-GPO -All | sort ModificationTime -Descending | select DisplayName, Id, ModificationTime -First 10
Get-ChildItem \\corp.local\SYSVOL -Recurse -Include *.ps1,*.bat,*.exe,*.vbs,ScheduledTasks.xml | ? {$_.LastWriteTime -gt $d} | select FullName, LastWriteTime

# KRBTGT đổi mật khẩu lần cuối
Get-ADUser krbtgt -Properties PasswordLastSet | select PasswordLastSet

# Dấu vết dump NTDS.dit
vssadmin list shadows
Get-ChildItem C:\ -Recurse -Include ntds.dit -ErrorAction SilentlyContinue | ? {$_.DirectoryName -notlike '*\NTDS'} | select FullName, LastWriteTime
```

Thay `corp.local` / `DC=corp,DC=local` / `DC01` bằng tên domain và DC của lab (`Get-ADDomain`).

## 8. Exfiltration và xóa dấu vết

Câu hỏi cần trả lời: dữ liệu nào bị gom, nén, gửi đi đâu, qua giao thức gì; attacker xóa gì để che dấu.

**\[SPLUNK\] Nén / gom dữ liệu**

```
index=* (CommandLine="*7z*a *" OR CommandLine="*rar*a *" OR CommandLine="*Compress-Archive*" OR CommandLine="*tar*-c*" OR CommandLine="*New-MailboxExportRequest*.pst*")
| table _time host user CommandLine
index=sysmon EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar" OR TargetFilename="*.pst") | table _time host Image TargetFilename
```

**\[SPLUNK\] Lưu lượng ra ngoài lớn bất thường**

```
index=firewall NOT dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats sum(bytes_out) as out by src_ip, dest_ip, dest_port | eval MB=round(out/1024/1024,2) | sort -out | head 20
```

**\[SPLUNK\] Công cụ tải lên / kết nối C2**

```
index=* (CommandLine="*curl*-T*" OR CommandLine="*curl*--upload*" OR CommandLine="*rclone*" OR CommandLine="*Invoke-WebRequest*-Method*Post*" OR CommandLine="*bitsadmin*" OR CommandLine="*ftp*")
| table _time host user CommandLine
index=sysmon EventCode=3 NOT DestinationIp IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) | stats count by host, Image, DestinationIp, DestinationPort | sort -count
```

**\[SPLUNK\] DNS tunneling** (subdomain dài, nhiều truy vấn tới một domain)

```
index=sysmon EventCode=22 | eval len=len(QueryName) | where len>50 | stats count by host, QueryName | sort -count
```

**\[SPLUNK\] Xóa dấu vết**

```
index=wineventlog EventCode IN (1102,104) | table _time host user
index=* (CommandLine="*wevtutil*cl*" OR CommandLine="*Clear-EventLog*" OR CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*sdelete*" OR CommandLine="*del *\\Temp\\*")
| table _time host user CommandLine
```

**\[HOST\] Khi log bị xóa, tìm bằng chứng thay thế:** Prefetch, PSReadLine history, TerminalServices logs, Sysmon log cục bộ (`Microsoft-Windows-Sysmon/Operational`), log của máy đích và firewall; Linux: `~/.bash_history`, `/var/log/auth.log`, `last`, `lastb`, `journalctl --since`.

```
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 500 | ? {$_.Id -in 1,3,11} | select TimeCreated, Id, Message
last -aiF | head -30; lastb | head -30; grep -E 'Accepted|Failed' /var/log/auth.log | tail -50
```

## 9. Giai đoạn 6 – Viết báo cáo

Báo cáo trình bày theo 6 giai đoạn (không theo từng máy); mỗi kết luận có query hoặc lệnh làm bằng chứng.

**Cấu trúc**

1. Thông tin chung: người điều tra, thời gian, phạm vi (Web, Jump, Mail, DC, VPN), nguồn dữ liệu, múi giờ.
2. Tóm tắt điều hành (5–7 dòng, viết sau cùng): chuyện gì, khi nào, vào bằng đường nào, ảnh hưởng, mức độ.
3. Sơ đồ chuỗi tấn công (mũi tên giữa các máy).
4. Quá trình điều tra chi tiết: Bước 1, 2, 3…
5. Timeline hợp nhất.
6. Ma trận ảnh hưởng theo máy.
7. IOC.
8. Mapping MITRE ATT&CK.
9. Đề xuất: ngăn chặn, loại bỏ, phục hồi, phòng ngừa.

**Mẫu một bước điều tra**

```markdown
**Bước N – <Tên bước>**
- Mục tiêu: <cần xác định điều gì>
- Nguồn dữ liệu: index=<...> sourcetype=<...> host=<...>  /  [HOST] <máy, lệnh>
- Truy vấn / lệnh: <SPL hoặc PowerShell/bash>
- Kết quả: <thời gian, host, user, IP, số liệu; ảnh chụp>
- Nhận định: <điều này chứng minh gì; xác nhận hay nghi ngờ; dẫn tới bước N+1 vì ...>
```

**Timeline hợp nhất** (sắp theo thời gian thực, không theo thứ tự bạn phát hiện)

| Thời gian | Host | Sự kiện | Bằng chứng | MITRE |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |
|  |  |  |  |  |

**Ma trận ảnh hưởng**

| Máy | Bị xâm nhập? | Cách thức | Quyền attacker đạt được | Bằng chứng (F#) |
| --- | --- | --- | --- | --- |
| WEB |  |  |  |  |
| MAIL |  |  |  |  |
| VPN |  |  |  |  |
| JUMP |  |  |  |  |
| DC |  |  |  |  |

**IOC**

| Loại | Giá trị | Thấy ở | Ghi chú |
| --- | --- | --- | --- |
| IP |  |  |  |
| Domain / URL |  |  |  |
| File + SHA256 |  |  |  |
| Tài khoản |  |  |  |

**MITRE ATT&CK thường gặp**

| Giai đoạn | Kỹ thuật |
| --- | --- |
| Initial Access | T1190 Exploit Public-Facing Application · T1566.001 Phishing Attachment · T1133 External Remote Services · T1078 Valid Accounts |
| Execution | T1059.001 PowerShell · T1059.003 Windows Command Shell |
| Persistence | T1505.003 Web Shell · T1136 Create Account · T1053.005 Scheduled Task · T1543.003 Windows Service · T1484.001 GPO Modification |
| Credential Access | T1110.003 Password Spraying · T1003.001 LSASS Memory · T1003.003 NTDS · T1003.006 DCSync · T1558.003 Kerberoasting · T1558.004 AS-REP Roasting |
| Lateral Movement | T1021.001 RDP · T1021.002 SMB/Admin Shares · T1550.002 Pass the Hash |
| Collection / Exfil | T1114.002 Remote Email Collection · T1560 Archive Collected Data · T1041 Exfiltration Over C2 · T1048 Exfiltration Over Alternative Protocol |
| Defense Evasion | T1070.001 Clear Windows Event Logs · T1027 Obfuscated Files |

**Đề xuất (theo thứ tự ưu tiên)**

1. **Ngăn chặn:** cách ly máy bị chiếm; ngắt phiên VPN; chặn IOC trên firewall, proxy, mail gateway; vô hiệu hóa tài khoản bị chiếm và tài khoản backdoor.
2. **Loại bỏ:** xóa webshell, malware, scheduled task, service, GPO độc; gỡ quyền DCSync và role assignment bị thêm; xóa mailbox export request lạ.
3. **Phục hồi:** reset mật khẩu tài khoản đặc quyền và tài khoản bị lộ; **reset KRBTGT 2 lần** nếu có DCSync/NTDS dump; vá CVE (Exchange CU/SU, web app, firmware VPN); theo dõi tăng cường.
4. **Phòng ngừa:** MFA cho VPN/OWA; chặn macro từ Internet; không publish ECP/PowerShell ra Internet; tiering admin (Domain Admin không đăng nhập Jump); LAPS, Credential Guard; mật khẩu mạnh cho tài khoản có SPN; alert Splunk cho 4720/4728/4662/1102/7045 và cho w3wp.exe sinh shell.

## 10. Phụ lục

### Windows Security Event ID

| ID | Ý nghĩa |
| --- | --- |
| 4624 / 4625 | Đăng nhập thành công / thất bại (xem Logon\_Type) |
| 4634 / 4647 | Đăng xuất |
| 4648 | Đăng nhập bằng credential tường minh (runas, PsExec) |
| 4672 | Đăng nhập có quyền đặc biệt (admin) |
| 4688 | Tạo tiến trình |
| 4698 | Tạo scheduled task |
| 4720 / 4722 / 4724 / 4726 | Tạo / bật / reset mật khẩu / xóa user |
| 4728 / 4732 / 4756 | Thêm vào nhóm global / local / universal |
| 4740 | Tài khoản bị khóa |
| 4768 / 4769 / 4771 | Kerberos TGT / TGS / pre-auth thất bại |
| 4776 | Xác thực NTLM |
| 4662 | Thao tác trên object AD (DCSync) |
| 5136 / 5137 | Sửa / tạo object AD (ACL, GPO) |
| 5140 / 5145 | Truy cập network share |
| 7045 | Cài service mới (System log) |
| 1102 / 104 | Xóa Security / System log |
| 4103 / 4104 | PowerShell module / script block logging |
| 21 / 24 / 25 | RDP logon / disconnect / reconnect (TerminalServices-LocalSessionManager) |

### Sysmon Event ID

| ID | Ý nghĩa |
| --- | --- |
| 1 | Tạo tiến trình (có CommandLine, ParentImage, Hashes) |
| 3 | Kết nối mạng |
| 7 | Nạp DLL |
| 8 | CreateRemoteThread (inject) |
| 10 | Truy cập tiến trình khác (lsass) |
| 11 | Tạo file |
| 12 / 13 | Tạo / sửa registry |
| 22 | Truy vấn DNS |

### Chữ ký nhanh

- `/ecp/*.js` + cookie `X-BEResource` → **ProxyLogon**
- `autodiscover.json?@` + `/powershell` + không user → **ProxyShell**
- cùng mẫu nhưng có user → **ProxyNotShell**
- `w3wp.exe` / `httpd` sinh `cmd.exe` / `sh` → **webshell**
- `WINWORD.EXE` sinh `powershell.exe` → **macro phishing**
- Sysmon 10 vào `lsass.exe` → **dump credential**
- 4769 + `0x17` nhiều SPN → **Kerberoasting**
- 4662 + `1131f6aa`/`1131f6ad` từ tài khoản không phải DC → **DCSync**

### Lệnh SPL hay dùng

| Lệnh | Dùng để |
| --- | --- |
| `stats count by ...` | Đếm, gom nhóm |
| `stats dc(x)` | Đếm giá trị khác nhau (spray, scan) |
| `min(_time)` + `convert ctime()` | Lần đầu xuất hiện |
| `table`, `sort`, `dedup`, `head` | Trình bày kết quả |
| `where`, `eval`, `coalesce()`, `cidrmatch()` | Lọc và chuẩn hóa field |
| `rex field=_raw "(?<ip>\d+\.\d+\.\d+\.\d+)"` | Tách field từ raw log |
| `iplocation` | Quốc gia của IP |
| `timechart span=1h` / `bin _time span=5m` | Xem theo thời gian |
| `transaction user maxspan=30m` | Gom phiên |
| `rare` / `sort count` | Tìm giá trị hiếm (thường là bất thường) |
| `fieldsummary` | Xem field có trong dữ liệu |

### Checklist trước khi nộp

- [ ] Mỗi máy đã trả lời: vào từ đâu, đi tiếp tới đâu
- [ ] Điểm xâm nhập đầu tiên có thời gian, IP, kỹ thuật (CVE nếu có)
- [ ] Mỗi kết luận có query/lệnh và kết quả đi kèm
- [ ] Phân biệt rõ "xác nhận" và "nghi ngờ"
- [ ] Timeline sắp theo thời gian thực, ghi múi giờ
- [ ] Sự kiện nhiễu / tấn công độc lập được nêu và giải thích
- [ ] IOC đầy đủ: IP, domain, file + hash, tài khoản
- [ ] Ma trận ảnh hưởng đủ 5 máy
- [ ] MITRE cho từng bước
- [ ] Đề xuất có thứ tự ưu tiên, có reset KRBTGT nếu domain bị chiếm
- [ ] Tóm tắt điều hành viết cuối cùng, đặt đầu báo cáo
