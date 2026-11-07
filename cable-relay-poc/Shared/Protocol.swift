//
//  Protocol.swift
//  cable-relay-poc — Shared wire protocol
//
//  This file is COMPILED INTO BOTH the iOS app and the Mac relay.
//  It defines the framing and message types for the caBLE/PXP relay
//  ceremony. Keep it free of platform imports (no CoreBluetooth,
//  no Network) so it drops cleanly into every target.
//
//  PXP ALIGNMENT (FIDO Proximity Exchange Protocol v1.0)
//  -----------------------------------------------------
//  - L2CAP CoC: INSECURE (no link-layer encryption), per PXP spec
//  - Noise handshake: NKpsk0 (P-256 / AES-256-GCM / SHA-256)
//  - PSK + responder static key: derived from shared QR secret
//  - Framing: 4-byte big-endian length prefix (identical on L2CAP and TCP)
//
//  THE PROPERTY UNDER TEST
//  -----------------------
//  The Noise NKpsk0 channel does NOT establish physical proximity. It
//  is relayable end-to-end with no cryptographic break. The relay
//  forwards opaque frames; both honest endpoints complete the ceremony
//  and agree a key, while the two radios that actually spoke are 1 m
//  apart and the "browser" is on another network entirely.
//

import Foundation

// MARK: - Framing
//
// Every logical message is length-prefixed: a 4-byte big-endian UInt32
// length, then that many bytes of payload. This is the SAME framing on
// the L2CAP stream (iPhone <-> iPad) and on the TCP bridge (iPad <-> Mac),
// which is the whole point: the relay copies frames between two transports
// without understanding them.

enum Frame {
    /// Encode a payload as length-prefixed bytes ready for any stream.
    static func encode(_ payload: Data) -> Data {
        var out = Data(capacity: 4 + payload.count)
        var len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(payload)
        return out
    }

    /// Pull as many complete frames as are available out of a mutable buffer.
    /// Leaves any trailing partial frame in `buffer` for the next read.
    static func drain(_ buffer: inout Data) -> [Data] {
        var frames: [Data] = []
        while buffer.count >= 4 {
            let len = buffer.prefix(4).withUnsafeBytes { raw in
                UInt32(bigEndian: raw.load(as: UInt32.self))
            }
            let total = 4 + Int(len)
            guard buffer.count >= total else { break }
            let payload = buffer.subdata(in: 4..<total)
            frames.append(payload)
            buffer.removeSubrange(0..<total)
        }
        return frames
    }
}

// MARK: - Messages
//
// A tiny JSON-tagged message set. JSON is used so the frames are human
// readable in your Wireshark/console traces — a deliberate research
// affordance, not a production choice.

enum MessageType: String, Codable {
    case handshakeInit      // browser  -> phone : NKpsk0 msg 1 (ePub + AEAD)  | PXP: Noise e, es
    case handshakeResp      // phone    -> browser: NKpsk0 msg 2 (ePub + AEAD) | PXP: Noise e, ee
    case assertionRequest   // browser  -> phone : "sign this challenge"        | caBLE: CTAP2 getAssertion
    case assertionResponse  // phone    -> browser: signature over challenge    | caBLE: CTAP2 assertion
    case proximityProbe     // browser  -> phone : app-layer RTT ping (demo)    | the thing that CANNOT bound a relay
    case proximityEcho      // phone    -> browser: RTT pong
}

struct Message: Codable {
    var type: MessageType
    /// Opaque body: NKpsk0 handshake messages or Crypter-sealed payloads.
    var body: Data?
    /// Monotonic nonce used only for the RTT probe demonstration.
    var probeNonce: UInt64?
    /// Sender's wall-clock micros, for the RTT readout (demo instrumentation).
    var tMicros: UInt64?

    init(type: MessageType, body: Data? = nil, probeNonce: UInt64? = nil, tMicros: UInt64? = nil) {
        self.type = type
        self.body = body
        self.probeNonce = probeNonce
        self.tMicros = tMicros
    }

    func encoded() -> Data { try! JSONEncoder().encode(self) }
    static func decode(_ data: Data) -> Message? { try? JSONDecoder().decode(Message.self, from: data) }
}

// MARK: - PSM advertising constant
//
// caBLE discovers the phone via a BLE advertisement carrying routing/nonce
// data. We model discovery with a fixed service UUID the phone advertises
// and the central scans for. The L2CAP PSM is negotiated dynamically by
// CoreBluetooth at publish time and handed to the central in a GATT read.

enum BLEIDs {
    // Pick your own 128-bit UUIDs; these are placeholders. Generate with
    // `uuidgen` and paste. Service carries a characteristic whose value is
    // the dynamic PSM (a UInt16) once the peripheral has published its CoC.
    static let serviceUUID   = "A1C3B2D4-0001-4A2B-9C3D-000000000001"
    static let psmCharUUID   = "A1C3B2D4-0002-4A2B-9C3D-000000000002"
}

func nowMicros() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1_000_000)
}
