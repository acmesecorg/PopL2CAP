//
//  PhonePeripheral.swift
//  cable-relay-poc — VICTIM PHONE role (runs on the iPhone)
//
//  Plays the authenticator. It:
//    1. Advertises a service and publishes an L2CAP CoC, exposing the
//       dynamic PSM via a GATT characteristic.
//    2. Accepts one L2CAP channel, runs the responder side of the
//       handshake, then answers an assertionRequest by "signing" the
//       challenge with its static identity.
//
//  It is an HONEST participant throughout. It cannot tell that the central
//  that connected (the iPad) is a relay collector rather than the real
//  browser. That blindness is the finding, not a bug in this code.
//
//  Core Bluetooth note: there is no raw L2CAP socket on Apple platforms.
//  publishL2CAPChannel(withEncryption:) is the only door to a CoC, and it
//  hands you a CBL2CAPChannel with paired In/OutputStreams. We drive those
//  streams manually below.
//

import Foundation
import CoreBluetooth
import CryptoKit

final class PhonePeripheral: NSObject, ObservableObject {

    @Published var log: [String] = []
    @Published var publishedPSM: CBL2CAPPSM = 0
    @Published var channelOpen = false

    private var manager: CBPeripheralManager!
    private var psmChar: CBMutableCharacteristic!
    private var service: CBMutableService!

    private var channel: CBL2CAPChannel?
    private var inBuffer = Data()
    private var outQueue = Data()

    private let identity = Identity()
    private lazy var noise = NoiseBox(role: .responder, staticKey: identity)

    func start() {
        manager = CBPeripheralManager(delegate: self, queue: .main)
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
        // Publish the CoC. withEncryption:true asks the stack to run the
        // LE Secure Connections pairing underneath; we also layer our own
        // handshake on top. The PSM comes back in the delegate below.
        p.publishL2CAPChannel(withEncryption: true)
    }

    func peripheralManager(_ p: CBPeripheralManager,
                           didPublishL2CAPChannel PSM: CBL2CAPPSM,
                           error: Error?) {
        if let e = error { line("publish error \(e.localizedDescription)"); return }
        publishedPSM = PSM
        line("published L2CAP PSM \(PSM)")
        // Stash the PSM so a central can read it over GATT.
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
        line("L2CAP channel opened from central")
        ch.inputStream.delegate = self
        ch.outputStream.delegate = self
        ch.inputStream.schedule(in: .main, forMode: .common)
        ch.outputStream.schedule(in: .main, forMode: .common)
        ch.inputStream.open()
        ch.outputStream.open()
    }
}

// MARK: - Stream handling + protocol
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
            line("<- handshakeInit")
            let resp = try! noise.makeResp(consuming: msg.body ?? Data())
            send(Message(type: .handshakeResp, body: resp))
            line("-> handshakeResp")

        case .handshakeFinal:
            line("<- handshakeFinal")
            try? noise.consumeFinal(msg.body ?? Data())
            line("session key established (responder)")

        case .assertionRequest:
            line("<- assertionRequest")
            // "Sign" the challenge: open the AEAD blob, sign, seal the result.
            // The challenge here stands in for CTAP2 clientDataHash.
            guard let sealed = msg.body,
                  let challenge = try? noise.open(sealed) else {
                line("could not open assertion request"); return
            }
            let signature = sign(challenge: challenge)
            let out = try! noise.seal(signature)
            send(Message(type: .assertionResponse, body: out))
            line("-> assertionResponse (SIGNED — victim just authed a session it never saw)")

        case .proximityProbe:
            // Immediately echo. The app-layer RTT this produces is uselessly
            // coarse (BLE connection interval + relay). See the Mac side read-out.
            send(Message(type: .proximityEcho, probeNonce: msg.probeNonce, tMicros: nowMicros()))

        default:
            break
        }
    }

    private func sign(challenge: Data) -> Data {
        // Ed25519 over the challenge with a per-launch signing key.
        // (Separate from the KA identity; CryptoKit keeps them distinct.)
        let signing = Curve25519.Signing.PrivateKey()
        let sig = try! signing.signature(for: challenge)
        var out = Data()
        out.append(signing.publicKey.rawRepresentation) // 32
        out.append(sig)                                  // 64
        return out
    }
}
