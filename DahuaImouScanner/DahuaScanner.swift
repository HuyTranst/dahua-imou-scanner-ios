import Foundation
import SwiftUI

// MARK: - Models

public struct DahuaDevice: Identifiable, Hashable {
    public let id: String // Use SerialNo or MAC as unique ID
    public let brand: Brand
    public let ip: String
    public let serialNo: String
    public let mac: String
    public let machineName: String
    public let deviceClass: String
    public let firmwareVersion: String
    public let tcpPort: Int
    public let httpPort: Int
    public let isInitialized: Bool
    public let subnetMask: String
    public let gateway: String
    public let dhcpEnabled: Bool
    public let vendor: String
    public let rawJson: String

    public enum Brand: String {
        case dahua = "Dahua"
        case imou = "Imou"
        case unknown = "Unknown"

        public var color: Color {
            switch self {
            case .dahua: return .red
            case .imou: return .orange
            case .unknown: return .gray
            }
        }
    }
}

// MARK: - JSON Mapping Structures

private struct NotifyDevInfoResponse: Decodable {
    let method: String?
    let params: DeviceParams?

    struct DeviceParams: Decodable {
        let deviceInfo: RawDeviceInfo?
    }

    struct RawDeviceInfo: Decodable {
        let Vendor: String?
        let mac: String?
        let DeviceClass: String?
        let DeviceType: String?
        let MachineName: String?
        let MachineGroup: String?
        let SerialNo: String?
        let Version: String?
        let Definition: String?
        let Port: Int?
        let HttpPort: Int?
        let VideoInputChannels: Int?
        let Init: Int?
        let IPv4Address: IPv4Details?

        struct IPv4Details: Decodable {
            let IPAddress: String?
            let SubnetMask: String?
            let DefaultGateway: String?
            let DhcpEnable: Bool?
        }
    }
}

// MARK: - Dahua / Imou UDP Scanner Engine

public class DahuaScanner: ObservableObject {
    @Published public var discoveredDevices: [DahuaDevice] = []
    @Published public var isScanning: Bool = false
    @Published public var statusMessage: String = "Sẵn sàng quét mạng LAN"

    private var socketFd: Int32 = -1
    private var scanWorkItem: DispatchWorkItem?
    private let queue = DispatchQueue(label: "com.dahua.scanner", qos: .userInitiated)

    public init() {}

    /// Bắt đầu quét các camera Dahua / Imou trong mạng LAN
    public func startScan(timeout: TimeInterval = 4.0) {
        guard !isScanning else { return }
        
        DispatchQueue.main.async {
            self.discoveredDevices.removeAll()
            self.isScanning = true
            self.statusMessage = "Đang quét mạng tìm camera Dahua / Imou..."
        }

        queue.async { [weak self] in
            guard let self = self else { return }
            self.performUdpDiscovery(timeout: timeout)
        }
    }

    /// Dừng quét
    public func stopScan() {
        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }
        scanWorkItem?.cancel()
        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Đã dừng quét. Tìm thấy \(self.discoveredDevices.count) thiết bị."
        }
    }

    // MARK: - Core Discovery Logic
    private func performUdpDiscovery(timeout: TimeInterval) {
        // 1. Khởi tạo POSIX UDP Socket
        socketFd = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFd >= 0 else {
            DispatchQueue.main.async {
                self.isScanning = false
                self.statusMessage = "Lỗi: Không thể khởi tạo UDP socket"
            }
            return
        }

        // Cho phép Broadcast
        var broadcastEnable: Int32 = 1
        setsockopt(socketFd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, socklen_t(MemoryLayout<Int32>.size))

        // Cho phép reuse address / port
        var reuse: Int32 = 1
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #if os(iOS)
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #endif

        // Set Timeout cho receive socket (500ms mỗi vòng lặp)
        var tv = timeval(tv_sec: 0, tv_usec: 500_000)
        setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Bind socket tới INADDR_ANY port 0 (OS tự cấp port ngẫu nhiên khả dụng)
        var bindAddr = sockaddr_in()
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_addr.s_addr = in_addr_t(0) // INADDR_ANY
        bindAddr.sin_port = in_port_t(0)

        let bindResult = withUnsafePointer(to: &bindAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(socketFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if bindResult < 0 {
            close(socketFd)
            socketFd = -1
            DispatchQueue.main.async {
                self.isScanning = false
                self.statusMessage = "Lỗi: Không thể bind socket"
            }
            return
        }

        // 2. Tạo gói tin DHIP Search Request
        let packet = buildSearchPacket()

        // 3. Gửi gói tin tới cả Broadcast (255.255.255.255) và Multicast (239.255.255.251) port 37810
        sendPacket(packet, toHost: "255.255.255.255", port: 37810)
        sendPacket(packet, toHost: "239.255.255.251", port: 37810)

        // 4. Vòng lặp nhận dữ liệu phản hồi từ camera trong khoảng thời gian timeout
        let startTime = Date()
        var buffer = [UInt8](repeating: 0, count: 65535)

        while Date().timeIntervalSince(startTime) < timeout && socketFd >= 0 {
            var senderAddr = sockaddr_in()
            var senderLen = socklen_t(MemoryLayout<sockaddr_in>.size)

            let bytesRead = withUnsafeMutablePointer(to: &senderAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(socketFd, &buffer, buffer.count, 0, $0, &senderLen)
                }
            }

            if bytesRead > 32 {
                let packetData = Data(buffer[0..<bytesRead])
                let senderIp = String(cString: inet_ntoa(senderAddr.sin_addr))
                parseIncomingPacket(packetData, senderIp: senderIp)
            }
        }

        // Đóng socket sau khi hết thời gian quét
        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }

        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Quét hoàn tất. Tìm thấy \(self.discoveredDevices.count) camera Dahua/Imou."
        }
    }

    /// Đóng gói gói tin DHIP Discovery Request theo chuẩn Dahua NetSDK
    private func buildSearchPacket() -> Data {
        // 32-byte DHIP Header:
        // Byte 0..3: Padding (0x00000000)
        // Byte 4..7: Magic identifier 'DHIP' (0x44, 0x48, 0x49, 0x50)
        // Byte 8..27: Reserved / flags
        // Byte 28..31: Header Size 0x20 (32 bytes Little Endian)
        var header = [UInt8](repeating: 0, count: 32)
        header[4] = 0x44 // 'D'
        header[5] = 0x48 // 'H'
        header[6] = 0x49 // 'I'
        header[7] = 0x50 // 'P'
        header[28] = 0x20 // 32 bytes header size

        // Payload JSON: {"method":"DHDiscover.search","params":{"mac":"","uni":0}}
        let jsonDict: [String: Any] = [
            "method": "DHDiscover.search",
            "params": [
                "mac": "",
                "uni": 0
            ]
        ]

        var data = Data(header)
        if let jsonData = try? JSONSerialization.data(withJSONObject: jsonDict, options: []) {
            data.append(jsonData)
        }
        return data
    }

    private func sendPacket(_ data: Data, toHost host: String, port: UInt16) {
        guard socketFd >= 0 else { return }

        var destAddr = sockaddr_in()
        destAddr.sin_family = sa_family_t(AF_INET)
        destAddr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &destAddr.sin_addr)

        _ = data.withUnsafeBytes { rawBuffer in
            withUnsafePointer(to: &destAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(socketFd, rawBuffer.baseAddress, data.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    /// Giải mã gói tin nhận về từ camera
    private func parseIncomingPacket(_ data: Data, senderIp: String) {
        // Kiểm tra xem có phải header DHIP không (Byte 4..7 phải là 'DHIP')
        guard data.count > 32 else { return }
        let magic = data.subdata(in: 4..<8)
        guard magic == Data([0x44, 0x48, 0x49, 0x50]) else { return }

        // Cắt bỏ 32 byte header để lấy chuỗi JSON
        let jsonPayloadData = data.subdata(in: 32..<data.count)
        guard let jsonString = String(data: jsonPayloadData, encoding: .utf8) ??
                               String(data: jsonPayloadData, encoding: .ascii) else {
            return
        }

        guard let parsed = try? JSONDecoder().decode(NotifyDevInfoResponse.self, from: jsonPayloadData),
              let info = parsed.params?.deviceInfo else {
            return
        }

        let serialNo = info.SerialNo ?? "Unknown-SN"
        let mac = info.mac ?? "Unknown-MAC"
        let machineName = info.MachineName ?? info.DeviceType ?? "Camera"
        let vendor = info.Vendor ?? "General"
        let deviceClass = info.DeviceClass ?? "IPC"
        let firmwareVersion = info.Version ?? "Unknown"
        let tcpPort = info.Port ?? 37777
        let httpPort = info.HttpPort ?? 80
        let isInit = (info.Init ?? 1) == 1
        let ip = info.IPv4Address?.IPAddress ?? senderIp
        let subnet = info.IPv4Address?.SubnetMask ?? "255.255.255.0"
        let gateway = info.IPv4Address?.DefaultGateway ?? "0.0.0.0"
        let dhcp = info.IPv4Address?.DhcpEnable ?? true

        // Phân loại Dahua vs Imou
        let brand: DahuaDevice.Brand
        let lowerVendor = vendor.lowercased()
        let lowerMachine = machineName.lowercased()

        if lowerVendor.contains("lechange") || lowerVendor.contains("imou") ||
            lowerMachine.hasPrefix("ipc-a") || lowerMachine.hasPrefix("ipc-c") ||
            lowerMachine.hasPrefix("ipc-f") || lowerMachine.hasPrefix("ipc-s") ||
            lowerMachine.contains("ranger") || lowerMachine.contains("cruiser") ||
            lowerMachine.contains("cue") || lowerMachine.contains("bullet") {
            brand = .imou
        } else if lowerVendor.contains("dahua") || lowerVendor.contains("general") ||
                  lowerMachine.hasPrefix("dh-") || lowerMachine.hasPrefix("ipc-h") ||
                  lowerMachine.hasPrefix("dhi-") {
            brand = .dahua
        } else {
            brand = .dahua // Mặc định là Dahua nếu thuộc hệ sinh thái
        }

        let device = DahuaDevice(
            id: serialNo != "Unknown-SN" ? serialNo : mac,
            brand: brand,
            ip: ip,
            serialNo: serialNo,
            mac: mac,
            machineName: machineName,
            deviceClass: deviceClass,
            firmwareVersion: firmwareVersion,
            tcpPort: tcpPort,
            httpPort: httpPort,
            isInitialized: isInit,
            subnetMask: subnet,
            gateway: gateway,
            dhcpEnabled: dhcp,
            vendor: vendor,
            rawJson: jsonString
        )

        DispatchQueue.main.async {
            // Tránh trùng lặp
            if let idx = self.discoveredDevices.firstIndex(where: { $0.id == device.id }) {
                self.discoveredDevices[idx] = device
            } else {
                self.discoveredDevices.append(device)
            }
        }
    }
}
