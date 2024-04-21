/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * bangchucaibang.xxx a còng gờ mail chấm com wrote this file.  As long as you
 * retain this notice you can do whatever you want with this stuff. If we meet 
 * some day, and you think this stuff is worth it, you can buy me a beer in return.
 * HTC
 * ----------------------------------------------------------------------------
 */

# Mục đích:
Scan COM GUID, CLSID, IID... 

# HDSD:
Chép hết tất cả vào 1 thư mục nào đó, chạy file script guidscan.py từ IDA, làm điếu thuốc hay ly cafe chờ nó chạy xong.

Thanks đã sử dụng, bug biếc có quăng ầm vô mặt em ở đây hay bên phê tê bút cũng được. 
HTC

# Các tools/scripts khác dùng chung sau khi chạy guidscan:

1. https://github.com/airbus-cert/comida 

Tool của Airbus CERT. Chưa được ưng ý lắm, vẫn rất chậm do query registry lại như COM Helper. Cần cải tiến.

2. py-com-tools: chịu khó gấu gồ. Tool rất mạnh, có thể thay comhelper2 của Servil
