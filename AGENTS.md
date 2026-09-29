# Project Guidelines & Memory: Quét IP tìm Dahua và Imou

Mỗi khi người dùng yêu cầu **"Quét IP tìm Dahua và Imou"** hoặc tích hợp module dò quét camera Dahua/Imou vào dự án này hoặc dự án khác, bạn phải tuân thủ nghiêm ngặt các nguyên tắc kỹ thuật sau:

1. **Giao thức & Port**:
   - Sử dụng UDP Port `37810` với gói tin DHIP 32-byte header + JSON `DHDiscover.search`.
   - Lắng nghe phản hồi `client.notifyDevInfo`.

2. **Các lỗi kinh điển đã khắc phục - Tuyệt đối không tái phạm**:
   - **Lỗi 1 (Trạng thái kích hoạt)**: Trường `Init` là bitmask số nguyên (406, 1158, 2182, 2714, 3206...). Tuyệt đối không kiểm tra `Init == 1`. Phải tính:
     ```swift
     let isInit = (initVal > 1) || (initVal & 2 != 0)
     ```
   - **Lỗi 2 (Trùng Serial Number làm mất camera)**: Thiết bị trong cùng một hệ thống có thể dùng chung SerialNo (ví dụ 192.168.1.80 và .153; .227 và .231). Định danh duy nhất phải dựa trên IP: `id = "\(ip)_\(serialNo)"`, và lưu danh sách so khớp theo `ip` (`$0.ip == device.ip`).
   - **Lỗi 3 (Tràn bộ đệm Wi-Fi làm rớt gói)**: Không bao giờ bắn 254 gói UDP trong 1ms. Phải có độ trễ tối thiểu `2.5ms` (`usleep(2500)`) giữa mỗi gói và chạy cơ chế 2 đợt quét (Đợt 1 toàn dải, chờ 1.8s, Đợt 2 quét bù).
   - **Lỗi 4 (Interface Wi-Fi)**: Phải ưu tiên tuyệt đối card Wi-Fi `en0`, không được để mạng di động `pdp_ip0` (10.x.x.x) ghi đè.
   - **Lỗi 5 (Nhận diện hãng)**: Nhận diện Imou qua vendor `LC`, `Lechange`, `Imou`, hoặc model tiền tố `IPC-A`, `IPC-C`, `IPC-F`, `IPC-S`, hoặc chứa tên `Ranger`, `Cruiser`, `Cue`, `Bullet`.
