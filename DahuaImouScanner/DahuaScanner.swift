import Foundation
import SwiftUI
import Network

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

// MARK: - Dahua / Imou Scanner Engine (Dual-Engine: UDP DHIP + TCP 37777 Check)

public class DahuaScanner: ObservableObject {
    @Published public var discoveredDevices: [DahuaDevice] = []
    @Published public var isScanning: Bool = false
    @Published public var statusMessage: String = "Sẵn sàng quét mạng LAN"
    @Published public var localIpAddress: String = "Đang kiểm tra..."
    @Published public var targetSubnetPrefix: String = "192.168.1"
    @Published public var scanLogs: [String] = []

    private var socketFd: Int32 = -1
    private let queue = DispatchQueue(label: "com.dahua.scanner", qos: .userInitiated)
    private var browser: NWBrowser?

    public init() {
        refreshLocalIp()
        triggerLocalNetworkPrivacyPrompt()
    }

    /// Kích hoạt popup xin quyền Local Network của Apple bằng Network.framework
    public func triggerLocalNetworkPrivacyPrompt() {
        let params = NWParameters()
        params.includePeerToPeer = true
        let browser = NWBrowser(for: .bonjour(type: "_dahua._udp", domain: nil), using: params)
        browser.stateUpdateHandler = { _ in }
        browser.start(queue: queue)
        self.browser = browser
    }

    /// Cập nhật IP hiện tại của iPhone
    /// Cập nhật IP hiện tại của iPhone (ưu tiên tuyệt đối Wi-Fi en0)
    public func refreshLocalIp() {
        let ips = getLocalIPv4Addresses()
        let preferredIp = ips.first(where: { $0.hasPrefix("192.168.") }) ??
                          ips.first(where: { !$0.hasPrefix("10.") && !$0.hasPrefix("127.") }) ??
                          ips.first ?? "192.168.1.94"

        DispatchQueue.main.async {
            self.localIpAddress = preferredIp
            let parts = preferredIp.split(separator: ".")
            if parts.count == 4 && !preferredIp.hasPrefix("10.") {
                self.targetSubnetPrefix = "\(parts[0]).\(parts[1]).\(parts[2])"
            } else if self.targetSubnetPrefix.hasPrefix("10.") || self.targetSubnetPrefix.isEmpty {
                self.targetSubnetPrefix = "192.168.1"
            }
        }
    }

    public func addLog(_ msg: String) {
        let timeStr = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        DispatchQueue.main.async {
            self.scanLogs.append("[\(timeStr)] \(msg)")
            if self.scanLogs.count > 100 {
                self.scanLogs.removeFirst()
            }
        }
    }

    /// Bắt đầu quét toàn diện
    public func startScan(timeout: TimeInterval = 4.0) {
        guard !isScanning else { return }

        var subnetToScan = targetSubnetPrefix.trimmingCharacters(in: .whitespacesAndNewlines)
        if subnetToScan.isEmpty || subnetToScan.hasPrefix("10.") {
            subnetToScan = "192.168.1"
            DispatchQueue.main.async {
                self.targetSubnetPrefix = "192.168.1"
            }
        }

        DispatchQueue.main.async {
            self.discoveredDevices.removeAll()
            self.scanLogs.removeAll()
            self.isScanning = true
            self.statusMessage = "Đang quét dải \(subnetToScan).1 - 254..."
        }

        addLog("Bắt đầu quét mạng Wi-Fi. Subnet: \(subnetToScan).0/24")

        queue.async { [weak self] in
            guard let self = self else { return }
            self.performDiscovery(subnet: subnetToScan, timeout: timeout)
        }
    }

    public func stopScan() {
        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }
        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Đã dừng quét. Tìm thấy \(self.discoveredDevices.count) camera."
        }
        addLog("Đã dừng quét.")
    }

    // MARK: - Core Discovery Logic
    private func performDiscovery(subnet: String, timeout: TimeInterval) {
        socketFd = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFd >= 0 else {
            DispatchQueue.main.async {
                self.isScanning = false
                self.statusMessage = "Lỗi: Không tạo được UDP socket"
            }
            addLog("Lỗi: Không tạo được UDP socket")
            return
        }

        var broadcastEnable: Int32 = 1
        setsockopt(socketFd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, socklen_t(MemoryLayout<Int32>.size))

        var reuse: Int32 = 1
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #if os(iOS)
        setsockopt(socketFd, SOL_SOCKET, SO_REUSEPORT, &reuse, socklen_t(MemoryLayout<Int32>.size))
        #endif

        var tv = timeval(tv_sec: 0, tv_usec: 150_000)
        setsockopt(socketFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

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
            addLog("Lỗi: Không bind được socket")
            return
        }

        // Tạo gói tin DHIP Search Request chuẩn xác
        let packet = buildDhipSearchPacket()

        // 1. Gửi Broadcast & Multicast
        addLog("Gửi UDP Broadcast 255.255.255.255:37810")
        sendPacket(packet, toHost: "255.255.255.255", port: 37810)
        sendPacket(packet, toHost: "239.255.255.251", port: 37810)
        sendPacket(packet, toHost: "\(subnet).255", port: 37810)

        // 2. Gửi Unicast Sweep qua tất cả 254 IP của dải mạng
        addLog("Quét Unicast 254 IP: \(subnet).1 -> \(subnet).254")
        for host in 1...254 {
            let targetIp = "\(subnet).\(host)"
            sendPacket(packet, toHost: targetIp, port: 37810)
        }

        // 3. Quét TCP 37777 song song (NetSDK Port Ping) để phát hiện camera dù bị chặn UDP
        checkTcpPortsAndProbe(subnet: subnet, packet: packet)

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
            self.statusMessage = "Hoàn tất! Tìm thấy \(self.discoveredDevices.count) camera."
        }
        addLog("Quét hoàn tất: Tìm thấy \(self.discoveredDevices.count) camera.")
    }

    /// Quét cổng TCP 37777 (NetSDK Port) để đảm bảo không bỏ sót bất kỳ camera nào
    private func checkTcpPortsAndProbe(subnet: String, packet: Data) {
        let group = DispatchGroup()
        for host in 1...254 {
            let ip = "\(subnet).\(host)"
            group.enter()
            queue.async {
                let s = socket(AF_INET, SOCK_STREAM, 0)
                if s >= 0 {
                    var tv = timeval(tv_sec: 0, tv_usec: 120_000)
                    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                    
                    var addr = sockaddr_in()
                    addr.sin_family = sa_family_t(AF_INET)
                    addr.sin_port = in_port_t(37777).bigEndian
                    inet_pton(AF_INET, ip, &addr.sin_addr)
                    
                    let res = withUnsafePointer(to: &addr) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                            connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                    close(s)
                    
                    if res == 0 {
                        self.addLog("Phát hiện cổng NetSDK 37777 MỞ tại \(ip)! Gửi gói tin DHIP...")
                        self.sendPacket(packet, toHost: ip, port: 37810)
                    }
                }
                group.leave()
            }
        }
    }

    /// Đóng gói gói tin DHIP Search Request chuẩn xác
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

        var header = [UInt8](repeating: 0, count: 32)
        header[0] = 0x20 // 32 bytes header size
        header[4] = 0x44 // 'D'
        header[5] = 0x48 // 'H'
        header[6] = 0x49 // 'I'
        header[7] = 0x50 // 'P'
        
        header[16] = UInt8(jsonLen & 0xFF)
        header[17] = UInt8((jsonLen >> 8) & 0xFF)
        header[18] = UInt8((jsonLen >> 16) & 0xFF)
        header[19] = UInt8((jsonLen >> 24) & 0xFF)

        header[24] = header[16]
        header[25] = header[17]
        header[26] = header[18]
        header[27] = header[19]

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

        let magic = data.subdata(in: 4..<8)
        guard magic == Data([0x44, 0x48, 0x49, 0x50]) else { return }

        guard let firstBrace = data.firstIndex(of: 0x7B),
              let lastBrace = data.lastIndex(of: 0x7D),
              lastBrace >= firstBrace else {
            return
        }

        let jsonSlice = data.subdata(in: firstBrace..<(lastBrace + 1))
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

        addLog(">>> Nhận diện thành công: [\(brand.rawValue)] \(machineName) tại \(ip) (SN: \(serialNo))")

        DispatchQueue.main.async {
            if let idx = self.discoveredDevices.firstIndex(where: { $0.id == device.id }) {
                self.discoveredDevices[idx] = device
            } else {
                self.discoveredDevices.append(device)
            }
        }
    }

    private func getLocalIPv4Addresses() -> [String] {
        var wifiAddresses: [String] = []
        var otherLanAddresses: [String] = []
        var cellularAddresses: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
            return ["192.168.1.94"]
        }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
        while let current = ptr {
            defer { ptr = current.pointee.ifa_next }
            
            guard let addrPtr = current.pointee.ifa_addr else { continue }
            let family = addrPtr.pointee.sa_family
            let flags = Int32(current.pointee.ifa_flags)
            let flagLoopback: Int32 = 0x8
            let flagUp: Int32 = 0x1

            if family == UInt8(AF_INET) && (flags & flagLoopback) == 0 && (flags & flagUp) != 0 {
                let ifName = String(cString: current.pointee.ifa_name)
                var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(addrPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let ipStr = String(cString: hostname)
                    if !ipStr.isEmpty && ipStr != "127.0.0.1" {
                        if ifName == "en0" || ifName.hasPrefix("en") {
                            wifiAddresses.append(ipStr)
                        } else if ifName.hasPrefix("pdp_ip") {
                            cellularAddresses.append(ipStr)
                        } else {
                            otherLanAddresses.append(ipStr)
                        }
                    }
                }
            }
        }

        // Ưu tiên số 1: Wi-Fi en0
        if let wifi = wifiAddresses.first {
            return [wifi]
        }
        // Ưu tiên số 2: Các dải 192.168.x
        if let lan = otherLanAddresses.first(where: { $0.hasPrefix("192.168.") }) {
            return [lan]
        }
        return wifiAddresses.isEmpty ? (otherLanAddresses.isEmpty ? ["192.168.1.94"] : otherLanAddresses) : wifiAddresses
    }
}
