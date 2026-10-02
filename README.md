<h1 align="center">VNPT Reverse Engineering & Rooting Project</h1>

***<h4 align="center">Không gì là không thể :)</h4>***

## 1: <ins>Mục tiêu</ins>
* Nghiên cứu về các modem nhà mạng 4 chữ (VNPT) (hiện tại đang nghiên cứu các dòng -H, -NS, -XS
* Phá firmware, tìm hiểu cơ chế encryption trong firmware (nếu ra và rảnh thì cố mod OpenWRT qua luôn)
* Vọc vạch hỏng modem thì có file để debrick (hiện tại chỉ có thể debrick cho dòng -H, -NS)
  
> [!CAUTION]
> **⚠️ Miễn trừ trách nhiệm ⚠️**<br>
> Tất cả nội dung chỉ nhằm mục đích nghiên cứu, học tập.<br>
> Không khuyến khích sử dụng vào các hoạt động vi phạm pháp luật hay xâm phạm hệ thống mạng.<br>
> Người sử dụng hoàn toàn tự chịu trách nhiệm.<br>
> Việc thực hiện theo các hành động đề cập trong này (kể cả cài ứng dụng) có thể khiến bạn mất internet hoặc hư hỏng router.


#### Mong được các anh dev bên VNPT chiếu cố.
---
## 2: <ins>Content</ins>
* [`flashdump/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/flashdump) NAND dump của firmware model GW-020H (sắp tới sẽ cập nhật thêm -XS, -NS)
* [`openwrt-initramfs-en751221/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/openwrt-initramfs-en751221) dùng để debrick nếu vọc vạch cháy firmware
* [`openwrt-xsw-050ns/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/openwrt-xsw-050ns) OpenWRT cho XSW050-NS (cảm ơn [@longnt2007](https://github.com/longnt2007) với đóng góp của bạn :3)
* [`tools/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/tools) các tool để decrypt và encrypt romfile.cfg
* Sắp tới sẽ cập nhật tool encrypt, decrypt cho dòng -XS (050)
* [`decrypted-cfgfile-xs/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/decrypted-cfgfile-xs) các mẫu file romfile.cfg của model đã decrypt
*  [`private-romfile-key/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/private-romfile-key) cert và private key cho decrypt và encrypt file .cfg model -XS
* Dump firmware đã được strip trong [`squashfs-modified`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/squashfs-modified):
	* `boa-dump.bin`: firmware gốc (GW020-H) trong quá trình upgrade qua web UI.
	* `squashfs.image`: phần squashfs đã được tách (GW020-H), có thể giải nén bằng `unsquashfs`.
	* Firmware đã dump đc từ boa của GW040-H
	* squashfs-root(đã giải mã) tại [đây](https://github.com/ResearcherPT/vnptmodemresearch/releases)
 *  [`Integrations/*`](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations) Hướng dẫn và tài nguyên, lệnh cài các phần mềm bổ sung, patch,...
---
## 3: <ins>Shell và những người bạn (TTY, SSH, ...)</ins>
* Mục này sẽ hướng dẫn mở shell (console) của router, nếu đã có thì bỏ qua, còn chưa thì tiếp~~
> [!WARNING]  
> **⚠️ CẢNH BÁO ⚠️**  
> Việc mở shell có thể vô tình tạo ra lỗ hổng ngay trên hệ thống mạng của bạn!  
> Hãy chắc chắn rằng chỉ có **BẠN** được phép truy cập vào.  
> Bằng việc bạn đặt mật khẩu đăng nhập vào WiFi khó đoán!
> Hãy sử dụng passwd và đổi pass ngay sau khi vào shell (nhớ đổi cho tất cả tài khoản), nếu không có thể thiết lập whitelist được quyền truy cập

### 3.1: UART
*Nếu bạn không thể kết nối qua UART cũng đừng lo, có cách không phải con thiệp phần cứng mà vẫn vào được shell cho cả dòng -H, -NS, -XS
* Chuẩn bị USB-UART (khuyến nghị chip CH340 hoặc FT232BL cho mấy khứa đỗ nghèo khỉ) và dây jumper.
* [Mở vỏ router](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/doc/disassemble) ra để thấy bo mạch
* Trên bo mạch gần đèn LED sẽ có 3 chân: `RX`, `TX`, `GND`.
* Kết nối đúng để tránh hỏng phần cứng (tự google xem hướng dẫn đi).
* Lưu ý đảm bảo kết nối tốt dây (có thể hàn cho lành)
### 3.2: Tài khoản login
* Khi boot lên và truy cập bằng uart sẽ thấy :
  ```txt
  Please press Enter to activate this console.
  ```
* Và connect vào thì sẽ có: `tc login:`
* Các credential cho -H, -NS:
  * admin / VnT3ch@dm1n (như root do full quyền,telnet,ssh,ftp)
  * operator / VnT3ch0per@tor (only UART)
  * customer / customer (quyền thấp,telnet,ssh)
  * user3 / star ( web, disable by default, quyền thấp, model -NS)

> [!IMPORTANT]
> Theo như các báo cáo thì chỉ mỗi customer / customer hoạt động ở trên dòng -H  
> Để thay đổi pass cho tài khoản admin thì bạn sẽ lấy romfile và decode ra tại [đây](https://huggingface.co/spaces/Expl01tHunt3r/file-decoder)  
> Sau khi có file decode thì bạn tìm tài khoản admin và nhìn qua mục ssh_passwd, tại đây bạn chỉ cần thay hash password theo ý của bạn vào đây  
> (hoặc lười quá copy hash pass của customer dán vào là xong)  
> Sau đó encode lại và up lên router để thay pass thôi  

* Riêng cho dòng -XS
  * customer / customer (quyền thấp, telnet)
  * admin / $2$7c1ae60c120167530ca98a32c5323d9b89cff5bb (hash, chưa tìm ra pass chính xác, telnet, console, ftp) ( `1234` , `s2@We3%Dc#` , `admin4444` )
  * operator / $1$y....DM.$7eLwNxxQmjB1WmfB.ancV/ (hash, chưa tìm ra pass chính xác, web) (`oper@tor`)
  * user3 / star ( web, disable by default, quyền thấp)

* Khi đăng nhập thành công sẽ vào trực tiếp shell mặc định (BusyBox Shell)
### 3.3: Telnet/SSH 
> [!TIP]
> Mình gọi Web-UI là trang để quản lý router với IP như [192.168.1.1](https://192.168.1.1/) hoặc [192.168.0.1](https://192.168.0.1/)  
> Gateway là IP của router, ví dụ như 192.168.1.1 hoặc 192.168.0.1  
> Mình sẽ nói theo giao diện tiếng anh
* Nếu bạn vào được Web-UI: Bạn vào Web-UI -> Đăng nhập -> Vào tab Access -> Vào mục ACL Filter -> Chọn Deactivated -> Và ấn Set
* Sau khi tắt ACL thì đối với:
  - Dòng -H: Sau khi làm yêu cầu trên thì bạn vào được rùi :D (AppleSang confirm nha, tắt cái là có thể shell luôn)
  
  - Dòng -NS: Ngay ở trang Web-UI thì ở đường dẫn vào web bạn xoá chữ ```content.asp``` thay bằng chữ ```getGateWay.cgi``` và truy cập sẽ có kết quả như ảnh dưới
    <img width="542" height="135" alt="image" src="https://github.com/user-attachments/assets/5574f71b-d030-4c07-813a-8035c7554c8a" />
    
  - Dòng -HS: **Chưa có thông tin**
    
  - Dòng -XS: Ngay ở trang Web-UI thì ở đường dẫn vào web bạn xoá chữ ```content.asp``` thay bằng chữ ```telnet.asp```, sau khi truy cập thì bạn tick ```TelnetSet: Enable``` và ấn   ```Save```
    <img width="1190" height="317" alt="image" src="https://github.com/user-attachments/assets/bceea390-af4c-4881-ac7a-ab641a913eca" />
    
* Sau khi làm xong bạn mở Command Prompt và nhập
```
telnet ip.gateway.của.bạn
```
Ví dụ như sau:
```bash
telnet 192.168.1.1
```
Hoặc đối với dòng -H, -NS thì có thể SSH, ví dụ như:
```bash
ssh admin@192.168.1.1
```

> [!WARNING]
> Nếu máy chưa có Telnet thì bật CMD **với quyền admin** và chạy lệnh sau
> ```bash
> dism /online /Enable-Feature /FeatureName:TelnetClient

Và quay lại [đây](https://github.com/ResearcherPT/vnptmodemresearch/blob/master/README.md#32-t%C3%A0i-kho%E1%BA%A3n-login) để đăng nhập vào shell  

* Nếu bạn không thể kích hoạt Telnet qua Web-UI thì có một cách hoạt động trên -NS, -XS (Bạn cũng có thể thử ở các dòng khác):
  - Chuẩn bị cho mình một que nhỏ như cây tăm-miễn có thể lọt vào nút Reset trên router là được
  - Sau khi chuẩn bị tinh thần, bạn lấy ngón tay **ấn thật mạnh** nút WPS, ngay khi đang ấn thì bạn lấy cây tăm đâm vào nút Reset và đẩy mạnh cây tăm vào để nút Reset bị ấn. Khi cả 2 nút đều đang ấn thì bạn nhìn đèn trên router và sẽ có hai trường hợp:
    - Đèn LOS nhấp nháy: Bạn bỏ tay ra **ngay lập tức** và chờ đợi router restart lại và thực hiện lại. **Nếu vẫn cố tình đè lâu thì router sẽ xoá hết config và buộc bạn phải setup lại từ đầu**
    - Đèn PON nhấp nháy: Bạn phải ấn giữ 2 nút trên trong tầm 6-7s, khi mà đèn PON nhấp nháy là bạn đã kích hoạt xong telnet và giờ có thể kết nối rồi nhé!
    - Nếu không thì còn một cách với tất cả các dòng, đăng nhập vào web quản trị (192.168.1.1) rồi tắt ACL đi thì sẽ truy cập telnet/ssh được
    - Lưu ý nho nhỏ là dòng XGS chỉ có telnet, không có ssh




---
## 4: <ins>Patch romfile.cfg</ins>
* `romfile.cfg` là file config lấy từ:
```
(Gateway IP) → Maintenance → Backup/Restore
```
* Các thông tin sau được lưu trong file:
  + LOID, mật khẩu LOID
  + SSID, mật khẩu Wi-Fi
  + Cấu hình mạng, firewall, cron, ...
* **Lưu ý:** File chứa nhiều thông tin nhạy cảm (ISP Username, thông tin cấu hình router, ...) nên không share cho bất kì ai ngoài project này nếu bạn cho phép. *Bạn sẽ không biết họ sẽ làm gì với tài khoản PPPoE của bạn đâu...*
* File cfg đã decrypt của dòng XS có thể tìm thấy trong data của repo này
### 4.1: Decrypt và chỉnh sửa
* `romfile.cfg` được encrypt bằng bộ mã hoá EVP_aes_256_cbc bởi binary `cfg_manager` (dòng -H) và `/userfs/bin/cfg` (dòng -NS,-XS)
* Key/IV của 2 dòng -H và -NS đã được reverse. 2 dòng sài 2 key/IV khác nhau riêng đối với dòng -XS sử dụng PKCS7 với private key đã được dump (chi tiết xem trong code dùng để decrypt/encrypt romfile )
* Có thể giải mã bằng tool trong repo (**Lưu ý: chọn đúng model để decrypt đúng file. Sai sẽ không đọc được, model cho dòng XS đang được code, xài tạm command trên máy để thay thế !**)
* Cách này còn có thể sử dụng để thêm script autostartup mà không phải cài patch (tuy nhiên chỉ hiệu quả với dòng -H do dòng -NS có cơ chế kiểm tra file backup khá nghiêm nên sẽ không chấp nhận file backup sau chỉnh sửa, dòng -XS cũng có cách để pack lại sau edit
	+ Cụ thể, với dòng -XS sau khi tải romfile.cfg từ webui thì có thể dùng command ( cài openssl ) hoặc tool python ( dùng cho trường hợp lấy config từ các dump mtd ) để decrypt
```bash
openssl smime -decrypt -inform DER -in path/to/romfile.cfg -out /whatever/romfile.cfd.dec -inkey path/to/romfile_encrypt_privatekey.pem
```

   + File privatekey.pem trên đã được up trong repo, lưu ý trỏ tới đúng file
   + Sau khi chỉnh sửa xong ( bạn có thể thay hash của các tài khoản để đặt lại mật khẩu tuỳ thích, đây chính là cách để có được admin shell trên model -XS hiện tại ), tool để gen hash đã có trong tools của repo này ), sau đó bạn phải pack ( encrypt ) lại file .cfg bằng lệnh
```bash
openssl smime -encrypt -inform DER -outform DER \
  -in /path/to/modified/romfile.cfg \
  -out /whatever/path/tp/outfile/romfile.cfg \
  /path/to/romfile_encrypt_cert.pem
```
   + file cert.pem trên là public key tương ứng với private key, có sẵn trong modem, hiện đã up lên repo này, bạn có thể tìm tại cùng thư mục với private key 
   + Xong! bạn có thể upload file backup và enjoy !
   + Lưu ý nho nhỏ, nêu bạn thay các hash trong web password (có đầu là $1$ ) thì sẽ làm khác một chút, ví dụ: bạn muốn đặt lại mật khẩu web cho user là admin với pass là 123456 thì bạn sẽ chạy lệnh sau để lấy hash:
```bash
openssl passwd -1 "uid = admin;psw = 123456"
```
rồi mới dùng hash này thay vào hash cũ, tương tự với các user khác, nếu đổi pass cho operator thì uid sẽ là operator , ... nếu password là 1234 thì chỗ psw sẽ là 1234, ...

* Hướng dẫn sử dụng đã có trong tool, chạy tool với argument trống sẽ in hướng dẫn
* Lưu ý từ bản T007 trở đi (trên 040NS) thì password telnet admin được generate từ SN của modem, bạn có thể xài tool theo hướng dẫn từ issue https://github.com/ResearcherPT/vnptmodemresearch/issues/23#issuecomment-5951961939 để get password
### 4.2: Yêu cầu để sử dụng tool
* Python (đã test từ bản 3.11.6 và có thể chạy từ 3.11.6 đổ lên, thực ra hầu hết các bản mới đều có thể chạy được) và có cài package pycryptodome `pip install pycryptodome`
* *chỉ vậy thôi*
### 4.3: Mở Telnet/SSH bằng cách edit romfile.cfg (*không mất sau reboot nhưng vẫn mất sau khi factory reset, dành cho dòng -H, -XS *)
* 1: Decrypt ``romfile.cfg``
* *Note: Nếu đọc file đã decrypt mà xuất hiện các ô ? (<img width="216" height="18" alt="image" src="https://github.com/user-attachments/assets/a164bc82-070f-4669-985d-dc05b7dc02a2" />) như này thì hãy kiểm tra các bước, ưu tiên sử dụng code python chạy local(các tool trên web dễ bị lỗi ) một khi file decrypt lỗi thì không thể xài để backup mà chỉ để đọc thông tin, cần file đầy đủ và không lỗi mới có thể backup lại lên modem ( do sẽ có double check content để xác minh tính hợp lệ )*
* 2 (-H): Tìm nơi quản lý Cron (trong file là \<Crond\>) và thêm
```bash
iptables -F INPUT; iptables -F FORWARD; iptables -F OUTPUT
```
Hoặc (trong trường hợp dấu ";" bị đánh là không hợp lệ )
```bash
iptables -I INPUT -p tcp --dport 22 -j ACCEPT
```
Ngoài lệnh này mọi người có thể thêm các lệnh khác nếu muốn.

* *Note1: Riêng đối với -XS, bạn có thể mở telnet bằng cách thay giá trị Active của các tài khoản là Yes, thông thường sẽ được active sẵn, bạn chỉ cần tắt ACL hoặc bấm nút như đã hướng dẫn, nếu không muốn thì hãy đăng nhập vào web quản trị và đi tới url `telnet.cgi` hoặc `telnet.asp` rồi chỉnh sang hoạt động.

*Tiếp ... nếu bạn đang làm trên model -H

* Trông nó sẽ như thế này (ở đây `/1 * * * *` nghĩa là lệnh sẽ chạy mỗi phút)
```xml
<Crond>
<CommandList Command_0="reboot" Command_1="" Command_2="" Command_3="" Command_4="" Command_5="" Command_6="" Command_7="" Command_8="" /> 
<Entry0 Active="1" NAME="rb" COMMAND="*/1 * * * * iptables -I INPUT -p tcp --dport 22 -j ACCEPT" />
<Entry1 Active="0" NAME="None" COMMAND="" />
<Entry2 Active="0" NAME="None" COMMAND="" />
<Entry3 Active="0" NAME="None" COMMAND="" />
<Entry4 Active="0" NAME="None" COMMAND="" />
<Entry5 Active="0" NAME="None" COMMAND="" />
<Entry6 Active="0" NAME="None" COMMAND="" />
<Entry7 Active="0" NAME="None" COMMAND="" />
<Entry8 Active="0" NAME="None" COMMAND="" />
</Crond>
```
* Sau đó encrypt lại và upload lên gateway webUI là được
---
## 5: <ins>Debrick với OpenWRT initramfs</ins>
* (Cho dòng -H) Khi modem bị brick:
	* Thử reboot (busybox reboot), restart boa nếu còn shell.
 	* Thử tắt bằng nút nguồn của router và bật lại
	* Nếu không truy cập được shell nốt:
 		* Mở nguồn cho modem
    	* Dùng OpenWrt initramfs để boot tạm (qua UART).
    	* Flash lại các file mtdX.bin từ backup.
    	* Khởi động lại và restore cấu hình (`romfile.cfg`), hoặc nếu muốn chắc hơn thì hãy tải lại firmware và update qua webUI 1 lần nữa.

## LJ: <ins> OpenWrt cho các dòng modem khác </ins>

* (Cho dòng -NS) Hãy tham khảo repo openwrt cho 040-ns (coming soon)
* (Cho dòng -XGS) Hãy tham khảo bản OpenWrt build bởi [@longnt2007](https://github.com/ResearcherPT/openwrt-xsw050ns)

* Tham khảo:

  * Hãy đọc và làm theo hướng dẫn tại mục [Debricking](https://openwrt.org/inbox/toh/tp-link/archer_vr1200v#debricking) của Router TP-Link Archer VR1200v đến từ OpenWRT.

 * Cảm ơn [@cjdelisle](https://github.com/cjdelisle) cho bản [initramfs](https://github.com/ResearcherPT/vnptmodemresearch/blob/master/openwrt-initramfs-en751221/openwrt-econet-en751221-en751221_generic-initramfs-kernel.bin)!
 * Hiện tại chưa xác định chính xác nhưng khả năng model XS lấy nền firmware từ 1 nhà sản xuất Trung Quốc: baidu (?)
---
## 6: <ins>Decode firmware từ `/tmp/boa-temp` (DEP!!!)</ins>
<details>
<summary>Chạy lệnh trong shell của modem(click to expand)</summary>
	
```shell
sed -i '1,$d' /tmp/auto_dump_boatemp.sh
cat >> /tmp/auto_dump_boatemp.sh <<'EOF'
#!/bin/sh
out="/tmp/yaffs/boa-dump.bin"
mkdir -p /tmp/yaffs

echo "[*] Waiting for /tmp/boa-temp to complete upload..."
last_size=0
stable_count=0

while true; do
    if [ -f /tmp/boa-temp ]; then
        set -- $(ls -l /tmp/boa-temp 2>/dev/null)
        size=$5

        if [ "$size" -gt 100000 ]; then
            if [ "$size" -eq "$last_size" ]; then
                stable_count=`expr $stable_count + 1`
            else
                stable_count=0
            fi
            last_size=$size

            # Nếu không đổi 2 lần liên tiếp (2 giây) => upload xong
            if [ "$stable_count" -ge 2 ]; then
                cp /tmp/boa-temp "$out"
                echo "[+] Dumped boa-temp ($size bytes) to $out"
                break
            fi
        fi
    fi
    sleep 1
done
EOF

chmod +x /tmp/auto_dump_boatemp.sh
```
</details>  

> [!DEP]  
> Hiện đã có repo và tool riêng cho việc trích xuất và chỉnh sửa firmware stock, vui lòng tham khảo tại [đây](https://github.com/ResearcherPT/gw040ns-firmware)

> [!NOTE]
> Trong dòng -NS thì sẽ không có mount phân vùng tên yaffs nên khi chạy script đó trên dòng -NS thì file đã dump vẫn sẽ bị mất khi upgrade xong  
> Khuyên đổi cái output path từ `/tmp/yaffs/*` qua `/tmp/userdata/*` nếu chạy trên dòng -NS,-XS

* Chạy script `/tmp/auto_dump_boatemp.sh`
* Upgrade firmware như bình thường
* Sau khi reboot xong, quay lại shell, lấy file `/tmp/userdata/boa-dump.bin` (`/tmp/yaffs/boa-dump.bin` nếu dòng -H) rồi có thể dùng `binwalk` hoặc `unsquashfs` để analyze
* **Lưu ý**
	* Có thể sửa file `boa-temp` trong quá trình upgrade để ép flash firmware tùy chỉnh, nhưng rủi ro brick rất cao nếu timing không chuẩn, không biết offset chính xác hay ghi đè file quan trọng.
	* Có thể kích hoạt upgrade thủ công qua việc chỉnh sửa nvram tên fw_upgrade qua tcapi (commit sau khi set) tuy nhiên phải qua được bước check firmware có hợp lệ không (hiện giờ thì thua).
---
## 7: <ins>.asp</ins>
* Trên các dòng của VNPT (chưa biết chính xác từ bản firm nào), các file .asp trong cgi-bin sẽ bị mã hoá, để tiện lợi cho việc mod firmware hay muốn đọc logic flow cần phải decode được file, trong khi nghiên cứu phát hiện file chỉ được mã hoá đơn giản bằng việc đảo bit, có thể decode bằng cách đảo bit lại.
* Code python để decode asp có trong `tools/asp-decoder.py`, chạy code sẽ có hướng dẫn.
* Khi mod file ASP, để tương thích với quy trình hoạt động cần phải encode và flash thay vào chỗ file cũ.
---
## 8: <ins>Ứng dụng</ins>
* [AdGuardHome](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/AdGuard)
* [ddns-updater](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/ddns_updater)
* Caddy (In progress)
* wolweb (In progress)
* [Btop](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/btop)
* [nano](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/nano)
> Đã có hướng dẫn cài trong README của các phần ứng dụng
---
## 9: Patch ( Với các dòng NS )
* [autorun](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/autorun)
* [myshell](https://github.com/ResearcherPT/vnptmodemresearch/tree/master/Integrations/myshell) 
---
## 10: <ins>Thảo luận</ins>
* [VOZ](http://voz.vn/t/vnptmodemresearch-%E2%80%94-nghien-cuu-firmware-root-modem-vnpt-can-anh-em-chung-tay.1159218)
* [Github](https://github.com/ResearcherPT/vnptmodemresearch/discussions/10)
* ~~Discord~~
---
## 11: <ins>Những mục tiêu sắp tới (Cho 040-NS)</ins>
* Cài được OpenWRT (Đã hoạt động trên -NS -> Đang thử nghiệm thêm driver PON -> ~~Release vào năm sau~~)
  * Cài được một loại VPN nào đó
* Tuỳ chỉnh chức năng cho nút WPS/WLan có những tính năng khác (Như lấy IP mới trong vòng 5s,...)
* Dễ dàng điều khiển led để báo hiệu những thông tin khác (Như mức sử dụng CPU, cảnh báo khi gần hết RAM,...)
* Custom được firmware để dễ dàng phát triển hơn (Như custom Web-UI, thêm bớt tính năng, tối ưu hiệu năng)
  * Đã release ngay tại [đây](https://github.com/ResearcherPT/gw040ns-firmware)
## Cập nhật
* Em đã làm 1 web online để có thể tự giải mã và mã hoá file mà không cần các bác phải cài này nọ tại [đây](https://huggingface.co/spaces/Expl01tHunt3r/file-decoder)
	* (hoặc dùng hosting Việt Nam với ping chỉ = 15ms!! -> https://cfgdecoder.fkrystal.qzz.io)
    > AppleSang: tin tôi đi, bạn sẽ thích tải tool về để tự mã hoá ra đó
* Do là free nên sẽ có lúc chập chờn, các bác chịu khó đợi, có thể xem status tại [đây](https://stats.uptimerobot.com/U65yw18Rtl)
* Hiện đã có key/iv cho dòng NS, đã cải tiến code để có thêm option cho dòng NS
* Xác nhận tool edit romfile đã chạy được với các model [GW020-H](https://www.vnpt-technology.vn/vi/product_detail/gpon-ont-igate-gw020-h), [GW240-H](https://www.vnpt-technology.vn/vi/product_detail/gpon-ont-igate-gw240-h), [GW040-H](https://www.vnpt-technology.vn/vi/product_detail/gpon-ont-igate-gw040-h), [GW040-NS](https://www.vnpt-technology.vn/vi/product_detail/gpon-ont-igate-gw040-ns) và command chạy được với model [GW050-XGS](https://www.vnpt-technology.vn/vi/product_detail/xgs-pon-ont-igate-xsw050-ns)
* Đã tìm được cách decode file .asp trong cgi-bin
* Các file cfg trên model có cấu trúc như sau nén gzip->header HD3R,version,length,...(256bytes)->data encrypt by PKCS7 structure

## Đóng góp:
- Xin cảm ơn 2 bạn [@BussyBakks](https://github.com/BussyBakks) và [@AppleSang](https://github.com/AppleSang) đã giúp em nghiên cứu thêm về key cho romfile.cfg dòng modem NS và cài các ứng dụng
- Xin cảm ơn [@longnt2007](https://github.com/longnt2007) đã port OpenWRT lên XSW050-NS


<p align="center">Made with ❤️ by Expl01tHunt3r</p>
