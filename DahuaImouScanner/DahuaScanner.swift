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
    public let initVal: Int
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
    public func startScan(timeout: TimeInterval = 6.5) {
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

        // Tăng bộ đệm nhận của Kernel lên 512KB để không bị rớt gói tin
        var rcvBufSize: Int32 = 512 * 1024
        setsockopt(socketFd, SOL_SOCKET, SO_RCVBUF, &rcvBufSize, socklen_t(MemoryLayout<Int32>.size))

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

        let packet = buildDhipSearchPacket()
        let scanStartTime = Date()

        // 1. TIẾN TRÌNH LẮNG NGHE ĐỘC LẬP TRÊN THREAD RIÊNG (LIÊN TỤC 100%, KHÔNG BỊ BLOCK)
        let listenGroup = DispatchGroup()
        listenGroup.enter()
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            defer { listenGroup.leave() }
            guard let self = self else { return }
            var buffer = [UInt8](repeating: 0, count: 65535)

            while self.isScanning && self.socketFd >= 0 && Date().timeIntervalSince(scanStartTime) < timeout {
                var senderAddr = sockaddr_in()
                var senderLen = socklen_t(MemoryLayout<sockaddr_in>.size)

                let bytesRead = withUnsafeMutablePointer(to: &senderAddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(self.socketFd, &buffer, buffer.count, 0, $0, &senderLen)
                    }
                }

                if bytesRead > 32 {
                    let packetData = Data(buffer[0..<bytesRead])
                    let senderIp = String(cString: inet_ntoa(senderAddr.sin_addr))
                    self.parseIncomingPacket(packetData, senderIp: senderIp)
                }
            }
        }

        // 2. CHẠY QUÉT TCP 37777 NON-BLOCKING (ĐỂ ĐÁNH THỨC CAMERA & GỬI TARGETED PROBE)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            self.checkTcpPortsAndProbe(subnet: subnet, packet: packet)
        }

        // 3. TIẾN TRÌNH PHÁT GÓI UDP ĐA ĐỢT (MULTI-ROUND PACED SENDER)
        func sendTargets(_ hosts: [Int], roundName: String) {
            self.addLog("\(roundName): Gửi unicast tới \(hosts.count) địa chỉ IP...")
            self.sendPacket(packet, toHost: "255.255.255.255", port: 37810)
            self.sendPacket(packet, toHost: "239.255.255.251", port: 37810)
            self.sendPacket(packet, toHost: "\(subnet).255", port: 37810)

            for host in hosts {
                guard self.isScanning && self.socketFd >= 0 else { break }
                let targetIp = "\(subnet).\(host)"
                // Gửi 2 gói cách nhau ngắn để chống rớt gói Wi-Fi
                self.sendPacket(packet, toHost: targetIp, port: 37810)
                usleep(1500)
                self.sendPacket(packet, toHost: targetIp, port: 37810)
                usleep(1500)
            }
        }

        // Đợt 1: Quét toàn bộ dải mạng 1...254
        sendTargets(Array(1...254), roundName: "Đợt 1")

        // Chờ 1.5 giây
        Thread.sleep(forTimeInterval: 1.5)

        // Đợt 2: Quét lại những IP chưa phản hồi
        if self.isScanning && self.socketFd >= 0 {
            let respondedIps = Set(self.discoveredDevices.map { $0.ip })
            let missingHosts = (1...254).filter { !respondedIps.contains("\(subnet).\($0)") }
            if !missingHosts.isEmpty {
                sendTargets(missingHosts, roundName: "Đợt 2 (Bổ sung)")
            }
        }

        // Chờ 1.5 giây
        Thread.sleep(forTimeInterval: 1.5)

        // Đợt 3: Đợt quét chốt chặn cuối cùng cho các camera ở xa/mạng yếu như Sau Vườn
        if self.isScanning && self.socketFd >= 0 {
            let respondedIps = Set(self.discoveredDevices.map { $0.ip })
            let missingHosts = (1...254).filter { !respondedIps.contains("\(subnet).\($0)") }
            if !missingHosts.isEmpty {
                sendTargets(missingHosts, roundName: "Đợt 3 (Chốt chặn)")
            }
        }

        // Chờ hết timeout
        let remaining = timeout - Date().timeIntervalSince(scanStartTime)
        if remaining > 0 {
            Thread.sleep(forTimeInterval: remaining)
        }

        if socketFd >= 0 {
            close(socketFd)
            socketFd = -1
        }
        _ = listenGroup.wait(timeout: .now() + 0.5)

        DispatchQueue.main.async {
            self.isScanning = false
            self.statusMessage = "Hoàn tất! Tìm thấy \(self.discoveredDevices.count) camera."
        }
        addLog("Quét hoàn tất: Tìm thấy \(self.discoveredDevices.count) camera.")
    }

    /// Quét cổng TCP 37777 (NetSDK Port) non-blocking để đánh thức camera và gửi probe tức thì
    private func checkTcpPortsAndProbe(subnet: String, packet: Data) {
        let semaphore = DispatchSemaphore(value: 30)
        let group = DispatchGroup()

        for host in 1...254 {
            let ip = "\(subnet).\(host)"
            semaphore.wait()
            group.enter()

            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                defer {
                    semaphore.signal()
                    group.leave()
                }
                guard let self = self, self.isScanning else { return }

                let s = socket(AF_INET, SOCK_STREAM, 0)
                guard s >= 0 else { return }
                defer { close(s) }

                // Chế độ non-blocking để không bị treo 75s trên các IP không có thiết bị
                let flags = fcntl(s, F_GETFL, 0)
                _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)

                var addr = sockaddr_in()
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = in_port_t(37777).bigEndian
                inet_pton(AF_INET, ip, &addr.sin_addr)

                let res = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }

                var isPortOpen = false
                if res == 0 {
                    isPortOpen = true
                } else if errno == EINPROGRESS {
                    var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
                    let pollRes = poll(&pfd, 1, 200) // 200ms timeout
                    if pollRes > 0 && (pfd.revents & Int16(POLLOUT)) != 0 {
                        var error: Int32 = 0
                        var len = socklen_t(MemoryLayout<Int32>.size)
                        getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len)
                        if error == 0 {
                            isPortOpen = true
                        }
                    }
                }

                if isPortOpen {
                    self.addLog("Phát hiện cổng NetSDK 37777 MỞ tại \(ip)! Gửi DHIP probe...")
                    // Gửi 3 gói UDP probe liên tiếp tới camera để đảm bảo nhận được phản hồi
                    for _ in 0..<3 {
                        self.sendPacket(packet, toHost: ip, port: 37810)
                        usleep(15000) // 15ms
                    }
                }
            }
        }
        group.wait()
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

        // Phân tích trạng thái kích hoạt chuẩn xác (Dahua / Imou Init Bitmask):
        // 0 hoặc 1: Chưa kích hoạt
        // > 1 hoặc có bit 1 (initVal & 2 != 0): Đã kích hoạt (406, 1158, 2182, 2714, 3206,...)
        let initVal = (dev["Init"] as? Int) ?? 0
        let isInit = (initVal > 1) || (initVal & 2 != 0)

        let ipv4Obj = dev["IPv4Address"] as? [String: Any]
        let ip = (ipv4Obj?["IPAddress"] as? String) ?? senderIp
        let subnet = (ipv4Obj?["SubnetMask"] as? String) ?? "255.255.255.0"
        let gateway = (ipv4Obj?["DefaultGateway"] as? String) ?? "0.0.0.0"
        let dhcp = (ipv4Obj?["DhcpEnable"] as? Bool) ?? true

        let brand: DahuaDevice.Brand
        let lowerVendor = vendor.lowercased()
        let lowerMachine = machineName.lowercased()

        if lowerVendor.contains("lechange") || lowerVendor.contains("imou") || lowerVendor == "lc" ||
            lowerMachine.hasPrefix("ipc-a") || lowerMachine.hasPrefix("ipc-c") ||
            lowerMachine.hasPrefix("ipc-f") || lowerMachine.hasPrefix("ipc-s") ||
            lowerMachine.contains("ranger") || lowerMachine.contains("cruiser") ||
            lowerMachine.contains("cue") || lowerMachine.contains("bullet") {
            brand = .imou
        } else {
            brand = .dahua
        }

        // Định danh duy nhất theo IP để không bao giờ bị ghi đè khi camera có nhiều IP hoặc trùng SN
        let deviceId = "\(ip)_\(serialNo)"

        let device = DahuaDevice(
            id: deviceId,
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
            initVal: initVal,
            subnetMask: subnet,
            gateway: gateway,
            dhcpEnabled: dhcp,
            vendor: vendor,
            rawJson: jsonString
        )

        addLog(">>> Nhận diện: [\(brand.rawValue)] \(machineName) tại \(ip) (SN: \(serialNo))")

        DispatchQueue.main.async {
            if let idx = self.discoveredDevices.firstIndex(where: { $0.ip == device.ip }) {
                self.discoveredDevices[idx] = device
            } else {
                self.discoveredDevices.append(device)
            }
            self.sortDiscoveredDevices()
        }
    }

    private func sortDiscoveredDevices() {
        self.discoveredDevices.sort { dev1, dev2 in
            let p1 = dev1.ip.split(separator: ".").compactMap { Int($0) }
            let p2 = dev2.ip.split(separator: ".").compactMap { Int($0) }
            if p1.count == 4 && p2.count == 4 {
                for i in 0..<4 {
                    if p1[i] != p2[i] {
                        return p1[i] < p2[i]
                    }
                }
            }
            return dev1.ip < dev2.ip
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
