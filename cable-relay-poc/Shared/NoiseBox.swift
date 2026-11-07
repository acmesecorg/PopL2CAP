//
//  PoCKeys.swift (was NoiseBox.swift)
//  cable-relay-poc — Shared key material for the NKpsk0 handshake
//
//  In real caBLE/PXP the PSK and responder static key are derived from the
//  QR code secret. Here we hardcode a 32-byte seed that both the phone and
//  the Mac derive from identically, simulating the QR exchange.
//

import Foundation
import CryptoKit

enum PoCKeys {
    static let qrSecret = Data([
        0x42, 0x6C, 0x75, 0x65, 0x53, 0x74, 0x65, 0x61,
        0x6C, 0x50, 0x6F, 0x50, 0x4C, 0x32, 0x43, 0x41,
        0x50, 0x2D, 0x50, 0x6F, 0x43, 0x2D, 0x51, 0x52,
        0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x21, 0x21
    ])

    static var psk: [UInt8] {
        [UInt8](HKDFShim.derive(
            ikm: qrSecret,
            salt: Data("cable-poc/psk".utf8),
            info: Data(), length: 32))
    }

    static var responderIdentity: P256.KeyAgreement.PrivateKey {
        let seed = HKDFShim.derive(
            ikm: qrSecret,
            salt: Data("cable-poc/identity".utf8),
            info: Data(), length: 32)
        return CableP256.deriveKeyFromSeed(seed)
    }

    static var responderPublicX962: [UInt8] {
        [UInt8](CableP256.exportPublicKeyX962(responderIdentity))
    }
}
