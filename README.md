# Dahua & Imou Scanner - iOS App

Ứng dụng iOS (SwiftUI) quét mạng Wi-Fi cục bộ (LAN), tự động nhận diện và trích xuất thông tin cấu hình chi tiết (Số SN, MAC, IP, Model, Firmware, Cổng TCP/HTTP, Vendor...) của camera **Dahua** và **Imou**.

Đã tích hợp sẵn cấu trúc **Xcode Project** và **GitHub Actions CI/CD** để tự động build ra file **`.ipa`** trực tiếp trên GitHub mà **không cần máy Mac**.

---

## 1. Cấu trúc thư mục dự án

```
DahuaImouScannerIOS/
├── .github/
│   └── workflows/
│       └── build-ipa.yml              # CI/CD tự động build IPA trên macOS runner của GitHub
├── DahuaImouScanner/
│   ├── DahuaScanner.swift             # Core Engine: UDP Broadcast/Multicast, giải mã DHIP & JSON
│   ├── ContentView.swift              # Giao diện SwiftUI: Danh sách camera, chi tiết & copy JSON
│   ├── DahuaImouScannerApp.swift      # Entry point
│   ├── Info.plist                     # Cấp quyền NSLocalNetworkUsageDescription (quét mạng LAN)
│   └── Assets.xcassets/               # Icon & Color asset catalog
├── DahuaImouScanner.xcodeproj/
│   ├── project.pbxproj                # File dự án Xcode chuẩn
│   └── xcshareddata/xcschemes/
│       └── DahuaImouScanner.xcscheme  # Shared Scheme để xcodebuild nhận diện
├── .gitignore
└── README.md
```

---

## 2. Các bước đưa lên GitHub để tự động build file `.ipa`

### Bước 1: Tạo một Repository mới trên GitHub
1. Truy cập [github.com/new](https://github.com/new).
2. Đặt tên repository (ví dụ: `dahua-imou-scanner-ios`).
3. Chọn chế độ **Public** hoặc **Private** tùy ý -> Bấm **Create repository**.

### Bước 2: Đẩy toàn bộ mã nguồn lên GitHub bằng Terminal / PowerShell
Mở PowerShell tại thư mục dự án (`C:\Users\Windows\.gemini\antigravity\scratch\DahuaImouScannerIOS`):

```powershell
# Di chuyển vào thư mục dự án
cd "C:\Users\Windows\.gemini\antigravity\scratch\DahuaImouScannerIOS"

# Khởi tạo git và commit
git init
git add .
git commit -m "feat: complete Dahua & Imou scanner iOS project with GitHub Actions"

# Đổi nhánh sang main
git branch -M main

# Liên kết với repository GitHub vừa tạo (thay URL bên dưới bằng repo của bạn)
git remote add origin https://github.com/TÊN_GITHUB_CỦA_BẠN/dahua-imou-scanner-ios.git

# Đẩy code lên GitHub
git push -u origin main
```

---

## 3. Cách lấy file `.ipa` sau khi GitHub build xong

1. Truy cập vào Repository trên GitHub của bạn.
2. Bấm vào tab **Actions** ở menu phía trên.
3. Bạn sẽ thấy một workflow có tên **"Build iOS IPA"** đang chạy (có icon hình tròn vàng nhấp nháy).
4. Đợi khoảng **2 - 4 phút** cho đến khi có icon **Tích xanh (Success)**.
5. Nhấp vào workflow đó -> Cuộn xuống mục **Artifacts** ở dưới cùng.
6. Bấm vào **`DahuaImouScanner-IPA`** để tải file zip về máy tính.
7. Giải nén file zip, bạn sẽ có file: **`DahuaImouScanner.ipa`**.

---

## 4. Cách cài đặt file `.ipa` vào iPhone

Vì file `.ipa` này được build dạng Unsigned (không cần nộp tài khoản Apple Developer $99/năm), bạn có thể cài vào iPhone bằng bất kỳ cách nào sau đây:

* **Cách 1: TrollStore (Khuyên dùng nếu máy hỗ trợ iOS 14 - 17.0)**:
  * AirDrop hoặc gửi file `.ipa` sang iPhone qua Telegram / Zalo / Drive.
  * Mở bằng TrollStore -> Bấm **Install** là xong ngay (Vĩnh viễn không bao giờ hết hạn chứng chỉ).

* **Cách 2: Sideloadly / AltStore (Phổ biến nhất trên Windows)**:
  * Tải **Sideloadly** (hoặc **AltStore**) trên máy tính Windows.
  * Cắm cáp kết nối iPhone với máy tính.
  * Kéo file `DahuaImouScanner.ipa` vào Sideloadly, nhập Apple ID miễn phí của bạn rồi bấm **Start**. Sideloadly sẽ tự ký và cài app vào iPhone.

* **Cách 3: ESign / Gbox / Scarlet (Ký trực tiếp trên iPhone)**:
  * Nhập file `.ipa` vào app ESign/Gbox/Scarlet trên iPhone và bấm Ký (Sign) bằng chứng chỉ cá nhân/doanh nghiệp.

---

## 5. Khi sử dụng app trên iPhone
* Mở app lần đầu, khi hệ thống hiện popup: *"DahuaImouScanner muốn tìm và kết nối với các thiết bị trên mạng cục bộ của bạn"*, hãy chọn **Cho phép (OK)**.
* Đảm bảo iPhone đang kết nối vào **cùng mạng Wi-Fi** với Camera Dahua / Imou.
* Bấm nút **Quét**: Toàn bộ camera sẽ xuất hiện đầy đủ kèm model, IP, MAC, Serial Number (SN) và cổng TCP. Bấm vào camera để xem toàn bộ chuỗi JSON gốc trả về.
