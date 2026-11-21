1. Cấu trúc báo cáo chuẩn
Thông tin chung: tên báo cáo, người điều tra, thời gian điều tra, phạm vi (web, jump, mail, DC, VPN), nguồn dữ liệu (các index/sourcetype trong Splunk).
Tóm tắt điều hành: 5–7 dòng: chuyện gì đã xảy ra, từ khi nào, kẻ tấn công vào bằng đường nào, gây ảnh hưởng gì, mức độ nghiêm trọng. Phần này viết sau cùng nhưng đặt lên đầu.
Quá trình điều tra chi tiết: các bước 1, 2, 3… Đây là phần chiếm nhiều điểm nhất.
Dòng thời gian sự cố (timeline).
Danh sách IOC: IP, domain, hash, tên file, tài khoản.
Mapping MITRE ATT&CK.
Đánh giá ảnh hưởng.
Đề xuất xử lý và khắc phục: ngăn chặn, loại bỏ, phục hồi, phòng ngừa.
2. Cách viết mỗi bước điều tra

Mỗi bước nên viết theo 5 ý cố định:

Bước N – [Tên bước]

Mục tiêu: cần xác định điều gì
Nguồn dữ liệu: index / sourcetype / host
Truy vấn: câu SPL đã dùng
Kết quả: số liệu, bảng hoặc ảnh chụp màn hình
Nhận định: kết quả này chứng minh điều gì, và vì sao dẫn sang bước tiếp theo

Ý cuối cùng quan trọng nhất. Thiếu phần nhận định thì bài chỉ là danh sách câu lệnh, giám khảo sẽ trừ điểm.

3. Bản mẫu (rút gọn)

TÓM TẮT
Ngày 15/11/2026, hệ thống bị xâm nhập qua email phishing gửi tới user nv.ketoan. Kẻ tấn công lấy được thông tin đăng nhập, truy cập VPN từ IP 185.x.x.x, sau đó qua Jump Server leo thang lên Domain Admin và thực hiện DCSync trên DC. Mức độ: Nghiêm trọng. Toàn bộ hash tài khoản domain có khả năng đã bị lộ.

Bước 1 – Khảo sát nguồn dữ liệu

Mục tiêu: xác định log nào có sẵn và khoảng thời gian của dữ liệu.
Truy vấn: | tstats count where index=* by index, sourcetype, host
Kết quả: có 5 index: web, mail, vpn, wineventlog, sysmon. Dữ liệu từ 14/11 đến 16/11.
Nhận định: đủ dữ liệu để truy vết toàn bộ chuỗi tấn công. Bắt đầu từ các điểm vào là mail, VPN và web.

Bước 2 – Phát hiện email đáng ngờ

Truy vấn: index=mail attachment="*.docm" | table _time sender recipient subject attachment
Kết quả: 15/11 08:12, billing@c0mpany.com gửi invoice_nov.docm tới nv.ketoan.
Nhận định: tên miền giả mạo (số 0 thay chữ o) và file Office có macro → nghi phishing. Cần kiểm tra file có được mở và thực thi không.

Bước 3 – Xác nhận mã độc thực thi

Truy vấn: index=sysmon EventCode=1 ParentImage="*WINWORD.EXE" | table _time host Image CommandLine
Kết quả: 08:15, WINWORD.EXE sinh ra powershell.exe -enc JABj.... Giải mã ra lệnh tải file từ hxxp://evil[.]xyz/a.ps1.
Nhận định: máy PC-KETOAN đã bị nhiễm và kết nối tới C2 evil[.]xyz. Bước tiếp theo: kiểm tra tài khoản của user có bị lạm dụng ở nơi khác không.

Bước 4 – Đăng nhập VPN bất thường

Truy vấn: index=vpn user=nv.ketoan action=success | iplocation src_ip | table _time src_ip Country assigned_ip
Kết quả: 15/11 02:03 (ngoài giờ), đăng nhập từ 185.x.x.x (nước ngoài), được cấp IP nội bộ 10.10.5.20.
Nhận định: tài khoản đã bị chiếm. Từ đây truy vết theo IP 10.10.5.20.

Bước 5 – Lateral movement sang Jump Server

Truy vấn: index=wineventlog host=JUMP01 EventCode=4624 Logon_Type=10 src_ip=10.10.5.20
Kết quả: RDP thành công vào JUMP01 lúc 02:10.
Kèm theo: Sysmon EventCode 10 cho thấy mimi.exe truy cập lsass.exe lúc 02:18, tức là đã dump credential.
Nhận định: kẻ tấn công lấy được credential của admin adm.it đang có phiên trên Jump.

Bước 6 – Leo quyền trên DC

Truy vấn: index=wineventlog host=DC01 EventCode IN (4720,4728) | table _time EventCode user Account_Name Group_Name
Kết quả: 02:31, adm.it tạo user svc_backup và thêm vào Domain Admins.
Nhận định: kẻ tấn công đã tạo tài khoản backdoor để duy trì truy cập.

Bước 7 – DCSync và xóa dấu vết

4662 có GUID replication (1131f6aa...) do svc_backup thực hiện từ JUMP01 lúc 02:40 → DCSync.
1102 lúc 02:55 → Security log bị xóa.

TIMELINE

Thời gian	    Host	      Sự kiện	Bằng chứng
15/11 02:03	  VPN	        Đăng nhập VPN từ 185.x.x.x	index=vpn
02:10	        JUMP01	    RDP từ 10.10.5.20	4624 type 10
02:18	        JUMP01	    Dump lsass	Sysmon 10
02:31	        DC01	      Tạo svc_backup, thêm vào Domain Admins	4720, 4728
02:40	        DC01	      DCSync	4662
02:55	        DC01	      Xóa log	1102
08:12	        MAIL	      Email phishing gửi tới nv.ketoan	index=mail

(Bạn sắp xếp lại các mốc theo đúng thứ tự thời gian thực trong dữ liệu. Trong mẫu này, VPN xảy ra trước email là để nhắc rằng thứ tự phát hiện có thể khác thứ tự tấn công, và bạn phải lý giải được điều đó, ví dụ: credential bị lộ từ một lần phishing trước đó.)

IOC: 185.x.x.x, evil[.]xyz, c0mpany.com, invoice_nov.docm (kèm hash nếu có), mimi.exe, tài khoản svc_backup.

MITRE: T1566.001 Phishing Attachment → T1059.001 PowerShell → T1133 External Remote Services (VPN) → T1021.001 RDP → T1003.001 LSASS Memory → T1136 Create Account → T1003.006 DCSync → T1070.001 Clear Windows Event Logs.

ĐỀ XUẤT

Ngăn chặn: cô lập PC-KETOAN và JUMP01; vô hiệu hóa svc_backup, nv.ketoan, adm.it; chặn các IOC trên firewall, proxy và mail gateway.
Loại bỏ: xóa mã độc; reset mật khẩu toàn bộ tài khoản đặc quyền; reset KRBTGT 2 lần vì đã có DCSync.
Phục hồi: kiểm tra lại GPO và các nhóm đặc quyền; theo dõi tăng cường trong 30 ngày.
Phòng ngừa: bật MFA cho VPN và mail; chặn macro từ Internet; giới hạn VPN theo vùng địa lý; triển khai LAPS và Credential Guard; tạo alert Splunk cho 4720/4728/1102/4662.
4. Mẹo lấy điểm
Ghi đủ thông tin cho mọi kết luận: thời gian, host, user, IP và câu truy vấn. Chụp màn hình kết quả Splunk nếu đề cho phép.
Phân biệt "xác nhận" và "nghi ngờ". Ví dụ: "Chưa đủ bằng chứng khẳng định dữ liệu bị exfil, tuy nhiên…". Giám khảo đánh giá cao sự chính xác này.
Chia thời gian: khoảng 60% để điều tra, 40% để viết. Ghi chú timeline ngay trong lúc tìm, đừng để cuối mới viết.
Bám theo chỉ dấu: dùng phát hiện của bước trước làm đầu vào cho bước sau (IP, rồi user, rồi host). Báo cáo sẽ tự có mạch logic.
Thống nhất múi giờ (UTC hay UTC+7) và ghi rõ trong báo cáo.
