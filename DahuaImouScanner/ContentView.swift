import SwiftUI
import UIKit

struct ContentView: View {
    @StateObject private var scanner = DahuaScanner()
    @State private var selectedDevice: DahuaDevice?
    @State private var showLogs: Bool = false

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                // Network Info Bar
                VStack(spacing: 8) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Circle()
                                    .fill(Color.green)
                                    .frame(width: 8, height: 8)
                                Text("IP iPhone: \(scanner.localIpAddress)")
                                    .font(.caption.bold())
                                    .foregroundColor(.secondary)
                            }
                            
                            HStack(spacing: 6) {
                                Text("Dải Subnet:")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                TextField("192.168.1", text: $scanner.targetSubnetPrefix)
                                    .textFieldStyle(RoundedBorderTextFieldStyle())
                                    .font(.system(.caption, design: .monospaced).bold())
                                    .frame(width: 110)
                                    .keyboardType(.numbersAndPunctuation)
                            }
                        }
                        
                        Spacer()

                        Button(action: {
                            if scanner.isScanning {
                                scanner.stopScan()
                            } else {
                                scanner.startScan(timeout: 4.5)
                            }
                        }) {
                            HStack(spacing: 6) {
                                if scanner.isScanning {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                        .scaleEffect(0.8)
                                    Text("Dừng")
                                } else {
                                    Image(systemName: "antenna.radiowaves.left.and.right")
                                    Text("Quét")
                                }
                            }
                            .font(.system(.subheadline, design: .rounded).bold())
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 8)
                            .background(scanner.isScanning ? Color.red : Color.blue)
                            .cornerRadius(10)
                            .shadow(color: (scanner.isScanning ? Color.red : Color.blue).opacity(0.3), radius: 4, y: 2)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.top, 10)
                    .padding(.bottom, 6)

                    // Status Bar
                    HStack {
                        Text(scanner.statusMessage)
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Spacer()
                        Button(action: {
                            showLogs.toggle()
                        }) {
                            Label(showLogs ? "Ẩn Log" : "Xem Log", systemImage: "terminal")
                                .font(.caption.bold())
                                .foregroundColor(.blue)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom, 8)
                }
                .background(Color(UIColor.secondarySystemBackground))

                Divider()

                // Live Logs Console (Collapsible)
                if showLogs {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text("NHẬT KÝ QUÉT THỜI GIAN THỰC")
                                .font(.caption2.bold())
                                .foregroundColor(.secondary)
                            Spacer()
                            Button("Xóa") {
                                scanner.scanLogs.removeAll()
                            }
                            .font(.caption2)
                        }
                        .padding(.horizontal, 8)
                        .padding(.top, 4)

                        ScrollView {
                            VStack(alignment: .leading, spacing: 2) {
                                ForEach(scanner.scanLogs, id: \.self) { log in
                                    Text(log)
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(log.contains(">>>") ? .green : (log.contains("Lỗi") ? .red : .primary))
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                            .padding(6)
                        }
                        .frame(height: 120)
                        .background(Color(UIColor.tertiarySystemBackground))
                        .cornerRadius(6)
                        .padding(.horizontal, 8)
                        .padding(.bottom, 6)
                    }
                    .background(Color(UIColor.secondarySystemBackground))
                    Divider()
                }

                // Devices List
                if scanner.discoveredDevices.isEmpty {
                    VStack(spacing: 16) {
                        Spacer()
                        Image(systemName: "video.badge.waveform")
                            .font(.system(size: 60))
                            .foregroundColor(.gray.opacity(0.6))
                        Text(scanner.isScanning ? "Đang dò tìm camera trong mạng..." : "Chưa tìm thấy camera")
                            .font(.headline)
                            .foregroundColor(.secondary)
                        Text("Nhấn nút 'Quét' để kiểm tra cả cổng TCP 37777 và UDP 37810 xuyên qua bộ lọc Wi-Fi.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                        Spacer()
                    }
                } else {
                    List {
                        Section(header: Text("Tìm thấy \(scanner.discoveredDevices.count) camera")) {
                            ForEach(scanner.discoveredDevices) { device in
                                DeviceRowView(device: device)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        selectedDevice = device
                                    }
                            }
                        }
                    }
                    .listStyle(InsetGroupedListStyle())
                }
            }
            .navigationBarTitle("Dahua & Imou Scanner", displayMode: .inline)
            .sheet(item: $selectedDevice) { device in
                DeviceDetailView(device: device)
            }
        }
        .navigationViewStyle(StackNavigationViewStyle())
    }
}

// MARK: - Row View
struct DeviceRowView: View {
    let device: DahuaDevice

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(device.brand.rawValue)
                    .font(.caption2.bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(device.brand.color)
                    .cornerRadius(4)

                Text(device.machineName)
                    .font(.headline)
                    .lineLimit(1)

                Spacer()

                Text(device.ip)
                    .font(.system(.subheadline, design: .monospaced).bold())
                    .foregroundColor(.primary)
            }

            HStack {
                Label(device.serialNo, systemImage: "number")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Spacer()

                if !device.mac.isEmpty {
                    Label(device.mac, systemImage: "network")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }

            HStack(spacing: 8) {
                Text("TCP: \(device.tcpPort)")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.blue.opacity(0.1))
                    .foregroundColor(.blue)
                    .cornerRadius(4)

                Text("HTTP: \(device.httpPort)")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.green.opacity(0.1))
                    .foregroundColor(.green)
                    .cornerRadius(4)

                Text(device.isInitialized ? "Đã kích hoạt" : "Chưa kích hoạt")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(device.isInitialized ? Color.gray.opacity(0.1) : Color.orange.opacity(0.2))
                    .foregroundColor(device.isInitialized ? .secondary : .orange)
                    .cornerRadius(4)

                Spacer()

                Image(systemName: "chevron.right")
                    .font(.caption2)
                    .foregroundColor(.gray)
            }
        }
        .padding(.vertical, 2)
    }
}

// MARK: - Detail Sheet View
struct DeviceDetailView: View {
    let device: DahuaDevice
    @Environment(\.presentationMode) var presentationMode
    @State private var copied: Bool = false

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Thông tin chung")) {
                    DetailRow(title: "Hãng sản xuất", value: "\(device.brand.rawValue) (\(device.vendor))")
                    DetailRow(title: "Tên Model / Sản phẩm", value: device.machineName)
                    DetailRow(title: "Loại thiết bị", value: device.deviceClass)
                    DetailRow(title: "Số Serial (SN)", value: device.serialNo, isMonospaced: true)
                    DetailRow(title: "Địa chỉ MAC", value: device.mac, isMonospaced: true)
                    DetailRow(title: "Firmware", value: device.firmwareVersion)
                    DetailRow(title: "Trạng thái kích hoạt", value: device.isInitialized ? "Đã kích hoạt (Init: 1)" : "Chưa kích hoạt (Init: 0)")
                }

                Section(header: Text("Cấu hình mạng & Cổng kết nối")) {
                    DetailRow(title: "Địa chỉ IP (IPv4)", value: device.ip, isMonospaced: true)
                    DetailRow(title: "Subnet Mask", value: device.subnetMask)
                    DetailRow(title: "Default Gateway", value: device.gateway)
                    DetailRow(title: "DHCP", value: device.dhcpEnabled ? "Bật (Enabled)" : "Tắt (Static IP)")
                    DetailRow(title: "Cổng TCP NetSDK", value: "\(device.tcpPort)")
                    DetailRow(title: "Cổng Web HTTP", value: "\(device.httpPort)")
                }

                Section(header: Text("JSON phản hồi gốc (notifyDevInfo)")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Button(action: {
                            UIPasteboard.general.string = device.rawJson
                            copied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                copied = false
                            }
                        }) {
                            HStack {
                                Image(systemName: copied ? "checkmark" : "doc.on.doc")
                                Text(copied ? "Đã sao chép vào bộ nhớ tạm" : "Sao chép toàn bộ JSON")
                            }
                            .font(.subheadline.bold())
                            .foregroundColor(.blue)
                        }

                        ScrollView(.horizontal, showsIndicators: true) {
                            Text(device.rawJson)
                                .font(.system(.caption, design: .monospaced))
                                .padding(8)
                                .background(Color(UIColor.tertiarySystemBackground))
                                .cornerRadius(8)
                        }
                    }
                }
            }
            .navigationBarTitle("Chi tiết thiết bị", displayMode: .inline)
            .navigationBarItems(trailing: Button("Đóng") {
                presentationMode.wrappedValue.dismiss()
            })
        }
    }
}

struct DetailRow: View {
    let title: String
    let value: String
    var isMonospaced: Bool = false

    var body: some View {
        HStack {
            Text(title)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(isMonospaced ? .system(.body, design: .monospaced).bold() : .body)
                .multilineTextAlignment(.trailing)
        }
    }
}
