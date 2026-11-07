//
//  PhonePeripheral.swift
//  cable-relay-poc — VICTIM PHONE role (runs on the iPhone)
//

import Foundation
import CoreBluetooth
import CryptoKit

final class PhonePeripheral: NSObject, ObservableObject {

    @Published var log: [String] = []
    @Published var publishedPSM: CBL2CAPPSM = 0
    @Published var channelOpen = false
    @Published var ceremonyState: CeremonyState = .idle

    enum CeremonyState: Equatable {
        case idle
        case advertising
        case channelConnected
        case handshakeComplete
        case signed
        case failed(String)
    }

    private var manager: CBPeripheralManager!
    private var psmChar: CBMutableCharacteristic!
    private var service: CBMutableService!

    private var channel: CBL2CAPChannel?
    private var inBuffer = Data()
    private var outQueue = Data()

    private lazy var staticKey = PoCKeys.responderIdentity
    private var crypter: Crypter?

    func start() {
        manager = CBPeripheralManager(delegate: self, queue: .main)
    }

    func retest() {
        line("--- RETEST: resetting for new ceremony ---")
        channel?.inputStream.close()
        channel?.outputStream.close()
        channel = nil
        channelOpen = false
        inBuffer = Data()
        outQueue = Data()
        crypter = nil
        ceremonyState = .advertising
        manager.publishL2CAPChannel(withEncryption: false)
    }

    private func line(_ s: String) {
        NSLog("[PHONE] %@", s)
        AxiomLog.shared?.log(s)
        DispatchQueue.main.async { self.log.append(s) }
    }

    private func setupService() {
        psmChar = CBMutableCharacteristic(
            type: CBUUID(string: BLEIDs.psmCharUUID),
            properties: [.read],
            value: nil,
            permissions: [.readable])
        service = CBMutableService(type: CBUUID(string: BLEIDs.serviceUUID), primary: true)
        service.characteristics = [psmChar]
        manager.add(service)
    }

    private func advertise() {
        manager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(string: BLEIDs.serviceUUID)],
            CBAdvertisementDataLocalNameKey: "cable-phone"
        ])
        line("advertising service \(BLEIDs.serviceUUID)")
    }
}

// MARK: - CBPeripheralManagerDelegate
extension PhonePeripheral: CBPeripheralManagerDelegate {

    func peripheralManagerDidUpdateState(_ p: CBPeripheralManager) {
        guard p.state == .poweredOn else { line("BLE state \(p.state.rawValue)"); return }
        setupService()
        p.publishL2CAPChannel(withEncryption: false)
    }

    func peripheralManager(_ p: CBPeripheralManager,
                           didPublishL2CAPChannel PSM: CBL2CAPPSM,
                           error: Error?) {
        if let e = error { line("publish error \(e.localizedDescription)"); return }
        publishedPSM = PSM
        ceremonyState = .advertising
        line("published INSECURE L2CAP PSM \(PSM)")
        var be = UInt16(PSM).bigEndian
        psmChar.value = Data(bytes: &be, count: 2)
        advertise()
    }

    func peripheralManager(_ p: CBPeripheralManager, didReceiveRead req: CBATTRequest) {
        if req.characteristic.uuid == psmChar.uuid, let v = psmChar.value {
            req.value = v
            p.respond(to: req, withResult: .success)
            line("served PSM to central")
        } else {
            p.respond(to: req, withResult: .attributeNotFound)
        }
    }

    func peripheralManager(_ p: CBPeripheralManager, didOpen channel: CBL2CAPChannel?, error: Error?) {
        if let e = error { line("channel open error \(e.localizedDescription)"); return }
        guard let ch = channel else { return }
        self.channel = ch
        channelOpen = true
        ceremonyState = .channelConnected
        line("L2CAP channel opened (insecure CoC)")
        ch.inputStream.delegate = self
        ch.outputStream.delegate = self
        ch.inputStream.schedule(in: .main, forMode: .common)
        ch.outputStream.schedule(in: .main, forMode: .common)
        ch.inputStream.open()
        ch.outputStream.open()
    }
}

// MARK: - Stream handling + NKpsk0 protocol
extension PhonePeripheral: StreamDelegate {

    func stream(_ aStream: Stream, handle event: Stream.Event) {
        switch event {
        case .hasBytesAvailable:
            readAvailable()
        case .hasSpaceAvailable:
            flush()
        case .errorOccurred:
            line("stream error")
        case .endEncountered:
            line("stream closed"); channelOpen = false
        default: break
        }
    }

    private func readAvailable() {
        guard let inp = channel?.inputStream else { return }
        var tmp = [UInt8](repeating: 0, count: 4096)
        while inp.hasBytesAvailable {
            let n = inp.read(&tmp, maxLength: tmp.count)
            if n > 0 { inBuffer.append(contentsOf: tmp[0..<n]) } else { break }
        }
        for frame in Frame.drain(&inBuffer) { handle(frame) }
    }

    private func send(_ msg: Message) {
        outQueue.append(Frame.encode(msg.encoded()))
        flush()
    }

    private func flush() {
        guard let out = channel?.outputStream, out.hasSpaceAvailable, !outQueue.isEmpty else { return }
        let n = outQueue.withUnsafeBytes { out.write($0.bindMemory(to: UInt8.self).baseAddress!,
                                                     maxLength: outQueue.count) }
        if n > 0 { outQueue.removeSubrange(0..<n) }
    }

    private func handle(_ frame: Data) {
        guard let msg = Message.decode(frame) else { line("undecodable frame"); return }
        switch msg.type {

        case .handshakeInit:
            line("<- handshakeInit (NKpsk0)")
            guard let body = msg.body,
                  let hs = CableHandshake.respond(
                      psk: PoCKeys.psk,
                      identity: staticKey,
                      message: [UInt8](body))
            else {
                line("NKpsk0 handshake FAILED")
                ceremonyState = .failed("Handshake failed")
                return
            }
            crypter = hs.result.crypter
            send(Message(type: .handshakeResp, body: Data(hs.response)))
            ceremonyState = .handshakeComplete
            line("-> handshakeResp; NKpsk0 session established (P-256/AES-GCM)")

        case .assertionRequest:
            line("<- assertionRequest")
            guard let c = crypter,
                  let sealed = msg.body,
                  let challenge = c.decrypt([UInt8](sealed))
            else {
                line("could not decrypt assertion request")
                ceremonyState = .failed("Decrypt failed")
                return
            }
            let signature = sign(challenge: Data(challenge))
            guard let out = c.encrypt([UInt8](signature)) else {
                line("could not encrypt assertion response")
                ceremonyState = .failed("Encrypt failed")
                return
            }
            send(Message(type: .assertionResponse, body: Data(out)))
            ceremonyState = .signed
            line("-> assertionResponse (SIGNED — victim authed a session it never saw)")

        case .proximityProbe:
            send(Message(type: .proximityEcho, probeNonce: msg.probeNonce, tMicros: nowMicros()))

        default:
            break
        }
    }

    private func sign(challenge: Data) -> Data {
        let signing = Curve25519.Signing.PrivateKey()
        let sig = try! signing.signature(for: challenge)
        var out = Data()
        out.append(signing.publicKey.rawRepresentation)
        out.append(sig)
        return out
    }
}
