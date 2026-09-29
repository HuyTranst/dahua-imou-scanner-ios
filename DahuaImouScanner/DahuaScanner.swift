import Foundation
import SwiftUI

// MARK: - Models

public struct DahuaDevice: Identifiable, Hashable {
    public let id: String
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

// MARK: - Dahua / Imou UDP Scanner Engine

public class DahuaScanner: ObservableObject {
    @Published public var discoveredDevices: [DahuaDevice] = []
    @Published public var isScanning: Bool = false
    @Published public var statusMessage: String = "Sẵn sàng quét mạng LAN"

    private var socketFd: Int32 = -1
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
            self.performDiscovery(timeout: timeout)
        }
    }

    /// Dừng quét
    public func stopScan() {
        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }
        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Đã dừng quét. Tìm thấy \(self.discoveredDevices.count) camera."
        }
    }

    // MARK: - Core Discovery Logic
    private func performDiscovery(timeout: TimeInterval) {
        // 1. Tạo UDP socket
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

        // Cho phép reuse address & port
        var reuse: Int32 = 1
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #if os(iOS)
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #endif

        // Set Timeout cho recvfrom (200ms mỗi lần lặp)
        var tv = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Bind socket tới cổng ngẫu nhiên khả dụng
        var bindAddr = sockaddr_in()
        bindAddr.sin_family = sa_family_t(AF_INET)
        bindAddr.sin_addr.s_addr = in_addr_t(0)
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

        // 2. Tạo gói tin DHIP Search Request chuẩn xác 100% theo Dahua NetSDK
        let packet = buildDhipSearchPacket()

        // 3. Lấy IP cục bộ của thiết bị để tính subnet và quét unicast sweep
        let localIps = getLocalIPv4Addresses()
        
        // Gửi Multicast và Global Broadcast port 37810
        sendPacket(packet, toHost: "255.255.255.255", port: 37810)
        sendPacket(packet, toHost: "239.255.255.251", port: 37810)

        // Gửi Subnet Broadcast và Unicast Sweep toàn dải (1..254)
        // Kỹ thuật này giúp vượt qua 100% các bộ định tuyến Wi-Fi chặn Broadcast/Multicast!
        for localIp in localIps {
            let parts = localIp.split(separator: ".")
            if parts.count == 4 {
                let subnetPrefix = "\(parts[0]).\(parts[1]).\(parts[2])"
                // Gửi subnet broadcast (ví dụ 192.168.1.255)
                sendPacket(packet, toHost: "\(subnetPrefix).255", port: 37810)
                
                // Unicast sweep toàn bộ subnet (1 -> 254)
                for host in 1...254 {
                    let targetIp = "\(subnetPrefix).\(host)"
                    sendPacket(packet, toHost: targetIp, port: 37810)
                }
            }
        }

        // 4. Lắng nghe phản hồi từ camera
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

        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }

        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Quét hoàn tất. Tìm thấy \(self.discoveredDevices.count) camera Dahua / Imou."
        }
    }

    /// Đóng gói gói tin DHIP Search Request chuẩn xác từng byte
    private func buildDhipSearchPacket() -> Data {
        let jsonDict: [String: Any] = [
            "method": "DHDiscover.search",
            "params": [
                "mac": "",
                "uni": 0
            ]
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: jsonDict, options: []) else {
            return Data()
        }

        let jsonLen = UInt32(jsonData.count)

        // 32-byte DHIP Header:
        // Byte 0..3: Header length = 32 (0x20, 0x00, 0x00, 0x00) Little-Endian
        // Byte 4..7: Magic ASCII 'DHIP' (0x44, 0x48, 0x49, 0x50)
        // Byte 8..15: 0x00 (Reserved)
        // Byte 16..19: jsonLen (Little-Endian)
        // Byte 20..23: 0x00 (Reserved)
        // Byte 24..27: jsonLen (Little-Endian)
        // Byte 28..31: 0x00 (Reserved)
        var header = [UInt8](repeating: 0, count: 32)
        header[0] = 0x20 // 32 bytes header size
        header[4] = 0x44 // 'D'
        header[5] = 0x48 // 'H'
        header[6] = 0x49 // 'I'
        header[7] = 0x50 // 'P'
        
        // Ghi jsonLen vào byte 16..19 và 24..27
        withUnsafeBytes(of: jsonLen.littleEndian) { rawBytes in
            for i in 0..<4 {
                header[16 + i] = rawBytes[i]
                header[24 + i] = rawBytes[i]
            }
        }

        var data = Data(header)
        data.append(jsonData)
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

    /// Giải mã gói tin phản hồi từ camera
    private func parseIncomingPacket(_ data: Data, senderIp: String) {
        guard data.count > 32 else { return }

        // Kiểm tra magic 'DHIP' ở byte 4..7
        let magic = data.subdata(in: 4..<8)
        guard magic == Data([0x44, 0x48, 0x49, 0x50]) else { return }

        // Cắt chuỗi JSON từ dấu '{' đầu tiên đến dấu '}' cuối cùng để loại bỏ byte rác/padding
        guard let firstBrace = data.firstIndex(of: 0x7B), // '{'
              let lastBrace = data.lastIndex(of: 0x7D),  // '}'
              lastBrace > firstBrace else {
            return
        }

        let jsonSlice = data.subdata(in: firstBrace...lastBrace)
        guard let jsonString = String(data: jsonSlice, encoding: .utf8) ??
                               String(data: jsonSlice, encoding: .ascii),
              let jsonObject = try? JSONSerialization.jsonObject(with: jsonSlice, options: []) as? [String: Any] else {
            return
        }

        let params = jsonObject["params"] as? [String: Any]
        guard let dev = params?["deviceInfo"] as? [String: Any] else {
            return
        }

        let serialNo = (dev["SerialNo"] as? String) ?? "SN-\(senderIp)"
        let mac = (dev["mac"] as? String) ?? (jsonObject["mac"] as? String) ?? ""
        let machineName = (dev["MachineName"] as? String) ?? (dev["DeviceType"] as? String) ?? "Camera"
        let vendor = (dev["Vendor"] as? String) ?? ""
        let deviceClass = (dev["DeviceClass"] as? String) ?? "IPC"
        let version = (dev["Version"] as? String) ?? ""
        let tcpPort = (dev["Port"] as? Int) ?? 37777
        let httpPort = (dev["HttpPort"] as? Int) ?? 80
        let isInit = ((dev["Init"] as? Int) ?? 1) == 1

        let ipv4Obj = dev["IPv4Address"] as? [String: Any]
        let ip = (ipv4Obj?["IPAddress"] as? String) ?? senderIp
        let subnet = (ipv4Obj?["SubnetMask"] as? String) ?? "255.255.255.0"
        let gateway = (ipv4Obj?["DefaultGateway"] as? String) ?? "0.0.0.0"
        let dhcp = (ipv4Obj?["DhcpEnable"] as? Bool) ?? true

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
        } else {
            brand = .dahua
        }

        let device = DahuaDevice(
            id: serialNo,
            brand: brand,
            ip: ip,
            serialNo: serialNo,
            mac: mac,
            machineName: machineName,
            deviceClass: deviceClass,
            firmwareVersion: version,
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
            if let idx = self.discoveredDevices.firstIndex(where: { $0.id == device.id }) {
                self.discoveredDevices[idx] = device
            } else {
                self.discoveredDevices.append(device)
            }
        }
    }

    /// Lấy danh sách IP nội bộ của iPhone / iPad
    private func getLocalIPv4Addresses() -> [String] {
        var addresses: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return ["192.168.1.1"]
        }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let current = ptr {
            defer { ptr = current.pointee.ifa_next }
            
            guard let addrPtr = current.pointee.ifa_addr else { continue }
            let family = addrPtr.pointee.sa_family
            let flags = Int32(current.pointee.ifa_flags)

            // Chỉ lấy IPv4 và bỏ qua loopback
            if family == UInt8(AF_INET) && (flags & IFF_LOOPBACK) == 0 && (flags & IFF_UP) != 0 {
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addrPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ipStr = String(cString: hostname)
                    if !ipStr.isEmpty && ipStr != "127.0.0.1" {
                        addresses.append(ipStr)
                    }
                }
            }
        }

        return addresses.isEmpty ? ["192.168.1.1"] : addresses
    }
}
