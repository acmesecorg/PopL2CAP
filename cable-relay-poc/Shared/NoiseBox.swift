//
//  NoiseBox.swift
//  cable-relay-poc — Abstract handshake / AEAD stand-in
//
//  This is a DELIBERATELY SIMPLIFIED model of the Noise XX handshake plus
//  transport encryption, using CryptoKit primitives that ship on both iOS
//  and macOS. It is NOT a conformant Noise implementation and must not be
//  used for anything real. It exists so the relay demo has genuine
//  asymmetric key agreement and authenticated encryption to forward,
//  without pulling in a full Noise dependency.
//
//  WHAT IT MODELS FAITHFULLY (and why that matters for the finding):
//   * Each side has a static identity keypair (Curve25519).
//   * They do an ephemeral ECDH + static ECDH, deriving a shared key via HKDF.
//   * Transport messages are sealed with ChaChaPoly (AEAD).
//   * Mutual authentication: each side proves possession of its static key.
//
//  THE RELAY POINT:
//   The relay never holds either static private key and never learns the
//   session key. It still completes the ceremony, because it only forwards
//   bytes. Confidentiality and authentication are INTACT end-to-end; what
//   fails is the inference "we share a key, therefore we are co-located."
//

import Foundation
import CryptoKit

/// Identity: a long-lived static keypair. In caBLE the phone's platform
/// authenticator holds an analogous device key; the "browser" holds the
/// QR-derived material. Here both sides generate one at launch.
struct Identity {
    let priv: Curve25519.KeyAgreement.PrivateKey
    var pub: Curve25519.KeyAgreement.PublicKey { priv.publicKey }
    init() { priv = Curve25519.KeyAgreement.PrivateKey() }
}

/// Minimal 3-message handshake state machine.
/// Roles: initiator = "browser", responder = "phone".
final class NoiseBox {

    enum Role { case initiator, responder }

    private let role: Role
    private let staticKey: Identity
    private var ephemeral: Curve25519.KeyAgreement.PrivateKey
    private var remoteEphemeral: Curve25519.KeyAgreement.PublicKey?
    private var remoteStatic: Curve25519.KeyAgreement.PublicKey?

    private(set) var sessionKey: SymmetricKey?
    private var sendCounter: UInt64 = 0
    private var recvCounter: UInt64 = 0

    init(role: Role, staticKey: Identity) {
        self.role = role
        self.staticKey = staticKey
        self.ephemeral = Curve25519.KeyAgreement.PrivateKey()
    }

    // --- Handshake wire bodies are just concatenated raw public keys here.
    //     A real Noise impl interleaves encryption into the handshake; we
    //     keep it legible. The security claim we care about (relay) holds
    //     regardless of this simplification.

    /// initiator -> responder : e
    func makeInit() -> Data {
        precondition(role == .initiator)
        return ephemeral.publicKey.rawRepresentation
    }

    /// responder consumes e, replies e + its static pub, derives key from ee+es-ish
    func makeResp(consuming initBody: Data) throws -> Data {
        precondition(role == .responder)
        remoteEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: initBody)
        var out = Data()
        out.append(ephemeral.publicKey.rawRepresentation)          // e
        out.append(staticKey.pub.rawRepresentation)                // s (responder static)
        try deriveIfPossible()
        return out
    }

    /// initiator consumes responder's (e,s), sends its own static pub, derives key
    func makeFinal(consuming respBody: Data) throws -> Data {
        precondition(role == .initiator)
        let eLen = 32
        let sLen = 32
        guard respBody.count >= eLen + sLen else { throw Err.badMessage }
        remoteEphemeral = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: respBody.prefix(eLen))
        remoteStatic = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: respBody.dropFirst(eLen).prefix(sLen))
        try deriveIfPossible()
        return staticKey.pub.rawRepresentation                     // s (initiator static)
    }

    /// responder consumes initiator static pub, finishes mutual auth
    func consumeFinal(_ finalBody: Data) throws {
        precondition(role == .responder)
        remoteStatic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: finalBody)
        try deriveIfPossible()
    }

    private func deriveIfPossible() throws {
        // Only key once BOTH ephemeral and remote-static are known, so both
        // sides mix the identical set of DH outputs (ee + ss) and agree the
        // same key. The responder keys on consumeFinal; the initiator on
        // makeFinal. Transport AEAD (the assertion step) runs after that.
        guard let re = remoteEphemeral, let rs = remoteStatic else { return }
        let ee = try ephemeral.sharedSecretFromKeyAgreement(with: re)
        let ss = try staticKey.priv.sharedSecretFromKeyAgreement(with: rs)

        // Order the two DH outputs canonically so both roles concatenate them
        // the same way regardless of who is initiator.
        let eeData = ee.withUnsafeBytes { Data($0) }
        let ssData = ss.withUnsafeBytes { Data($0) }
        var ikm = Data()
        ikm.append(eeData)
        ikm.append(ssData)

        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: Data("cable-relay-poc/v1".utf8),
            info: Data("session".utf8),
            outputByteCount: 32)
        sessionKey = key
    }

    // --- Transport AEAD over the established key. ---

    func seal(_ plaintext: Data) throws -> Data {
        guard let key = sessionKey else { throw Err.noKey }
        let nonce = counterNonce(&sendCounter)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
        return box.combined
    }

    func open(_ ciphertext: Data) throws -> Data {
        guard let key = sessionKey else { throw Err.noKey }
        let box = try ChaChaPoly.SealedBox(combined: ciphertext)
        let pt = try ChaChaPoly.open(box, using: key)
        recvCounter &+= 1
        return pt
    }

    private func counterNonce(_ c: inout UInt64) -> ChaChaPoly.Nonce {
        var raw = Data(count: 12)
        var be = c.bigEndian
        withUnsafeBytes(of: &be) { raw.replaceSubrange(4..<12, with: $0) }
        c &+= 1
        return try! ChaChaPoly.Nonce(data: raw)
    }

    enum Err: Error { case badMessage, noKey }
}
