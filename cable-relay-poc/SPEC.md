# caBLE / FIDO Hybrid Transport — L2CAP Relay PoC

**Specification + reference implementation**
Crainiate Labs — Blue Steal research
Status: draft PoC · Target: Apple hardware (iPhone + iPad + Mac)

---

## 0. Purpose and the claim under test

This PoC was built to answer one question from the Blue Steal research:

> *Does establishing a direct, connection-oriented channel (BLE L2CAP CoC)
> instead of a replayable broadcast advertisement close the proximity-relay?*

It does not. The PoC is constructed to **demonstrate the negative result**
concretely, so the dead-end is documented rather than asserted.

**Falsifiable claim:** *A connection-oriented, encrypted,
mutually-authenticated channel does not establish physical proximity. It is
relayable end-to-end with no cryptographic break: both honest endpoints
complete the ceremony and agree a session key, while the two radios that
actually spoke are ~1 m apart and the authenticating "browser" is on a
different network.*

If the PoC runs and the Mac prints a valid assertion over a phone it only
ever reached through the relay, the claim stands.

---

## 1. Threat model

| Party | Honest? | Controlled by | Notes |
|---|---|---|---|
| Victim phone (authenticator) | **Honest** | Victim | Holds credential; blind to being relayed |
| Collector radio | Malicious | Attacker | ~1 m from victim phone; genuine BLE proximity |
| Tunnel / bridge | Neutral pipe | Public infra | Dumb encrypted byte bridge (modelled as TCP) |
| Relay-browser | Malicious | Attacker | The "laptop"; on another network; holds QR-derived keys |
| Relying party | Honest | Service | Off-model here; the assertion would satisfy it |

Two structural facts drive every result:

1. **The attacker owns the browser endpoint outright.** Nothing it
   measures or reports is trustworthy. This voids laptop-side timing,
   ambient-radio fingerprinting, and laptop-attested context.
2. **The victim's phone is honest but blind.** It will faithfully answer any
   correctly-keyed request. Any proof an honest phone can produce, the relay
   harvests. (The *willing-party test*: if the honest phone can produce the
   proof, the relay wins.)

---

## 2. Roles and physical topology

```
   ┌─────────────┐   BLE L2CAP CoC    ┌──────────────┐   TCP (tunnel)   ┌──────────────┐
   │  iPhone     │◄──────────────────►│  iPad         │◄───────────────►│  Mac          │
   │  VICTIM     │   ~1 metre          │  COLLECTOR    │  cross-network   │  RELAY-BROWSER│
   │  peripheral │                     │  central+pump │                  │  initiator+RP │
   └─────────────┘                     └──────────────┘                  └──────────────┘
      honest                              no crypto                          honest crypto
      authenticator                       pure byte pump                      attacker laptop
```

- The **iPhone** and **iPad** are physically together (genuine proximity).
- The **Mac** is deliberately elsewhere — different Wi-Fi, a tether, or over
  a VPN — to make "radio distance erased, network distance preserved" visible.

---

## 3. Channel: why L2CAP CoC, and the Apple constraint

Apple platforms expose **no raw L2CAP socket** (no `AF_BLUETOOTH` /
`BTPROTO_L2CAP` as on Linux/BlueZ). The only route to a connection-oriented
channel is Core Bluetooth's L2CAP Channel feature:

- Peripheral: `publishL2CAPChannel(withEncryption:)` → returns a dynamic
  **PSM**; a `CBL2CAPChannel` arrives via `didOpen`.
- Central: `openL2CAPChannel(_ psm:)` → `CBL2CAPChannel` via `didOpen`.
- Both sides drive the paired `InputStream` / `OutputStream`.

`withEncryption: true` runs LE Secure Connections pairing beneath the CoC.
This is worth stressing in the writeup: **even with link-layer encryption
AND an application-layer Noise handshake on top, the relay is unaffected**,
because the collector terminates the pairing honestly on the phone side and
re-originates on the TCP side. Encryption protects content, not location.

Discovery is modelled with a GATT service whose characteristic returns the
dynamic PSM (`BLEIDs` in `Shared/Protocol.swift`). In real caBLE the BLE
advertisement carries routing/nonce data; the correspondence is noted inline.

---

## 4. Wire protocol

### 4.1 Framing (`Shared/Protocol.swift`)
`[4-byte big-endian length][payload]`. **Identical** on the L2CAP stream and
the TCP bridge — that identity is the point: the collector copies frames
between transports without parsing them.

### 4.2 Messages
JSON-tagged (for readable traces), sealed bodies where applicable:

| Type | Direction | caBLE analogue |
|---|---|---|
| `handshakeInit` | browser → phone | Noise `e` |
| `handshakeResp` | phone → browser | Noise `e, ee, s` |
| `handshakeFinal` | browser → phone | Noise `s, se` |
| `assertionRequest` | browser → phone | CTAP2 `getAssertion` |
| `assertionResponse` | phone → browser | CTAP2 assertion |
| `proximityProbe` / `proximityEcho` | both | app-layer RTT (shown to be useless) |

### 4.3 Crypto (`Shared/NoiseBox.swift`)
A **simplified stand-in** for Noise XX + transport AEAD, over CryptoKit
(Curve25519 ECDH, HKDF-SHA256, ChaChaPoly). Mutual auth via static-key ECDH.
**Not conformant Noise — do not ship.** The relay result is independent of
this simplification: swap in a real Noise library (e.g. a Swift Noise impl)
and nothing about the outcome changes.

---

## 5. Ceremony sequence

```
Mac (initiator)          iPad (pump)           iPhone (responder)
   │ handshakeInit ───────► relay ─────────────► makeResp
   │                                             (derive key)
   │ ◄──────── relay ◄──────── handshakeResp ◄───┤
   │ makeFinal                                   │
   │ handshakeFinal ──────► relay ─────────────► consumeFinal
   │ (key agreed, end-to-end, THROUGH the relay) (key agreed)
   │ proximityProbe ──────► relay ─────────────► echo
   │ ◄── RTT readout: ~tens of ms, uninformative ┤
   │ assertionRequest ────► relay ─────────────► sign(challenge)
   │ ◄──────── relay ◄──────── assertionResponse ┤
   │ verify = true                               │
   ▼ "victim authenticated a session they never initiated"
```

---

## 6. Build & run

### 6.1 iOS app (iPhone + iPad)
1. New Xcode project → **iOS App**, SwiftUI, name e.g. `CableRelay`.
2. Add to the target: `iOSApp/App.swift`, `iOSApp/PhonePeripheral.swift`,
   `iOSApp/CollectorCentral.swift`, `Shared/Protocol.swift`,
   `Shared/NoiseBox.swift`.
3. Info.plist: add `NSBluetoothAlwaysUsageDescription` and
   `NSLocalNetworkUsageDescription` (string values, any text).
4. Signing: free personal team is fine; both devices on your Apple ID.
5. Install on **both** devices. Launch, pick **Phone** on the iPhone and
   **Collector** on the iPad.

### 6.2 Mac relay-browser
```bash
cd MacRelay
swiftc -O main.swift ../Shared/Protocol.swift ../Shared/NoiseBox.swift -o relaybrowser
./relaybrowser         # listens on :7070
```

### 6.3 Wire it up
1. Start `./relaybrowser` on the Mac. Note the Mac's IP reachable from the
   iPad (LAN, or a VPN/tether address for a true cross-network demo).
2. iPhone → **Phone** role → it advertises and publishes a PSM.
3. iPad → **Collector** role → enter the Mac's IP → **Start**.
4. Watch: iPad opens L2CAP to the phone, connects TCP to the Mac, and the
   Mac drives the ceremony to completion. The Mac prints the agreed key, the
   RTT readout, and the valid assertion.

### 6.4 The visible result
Put the iPhone and iPad on a desk together; put the Mac in another room on a
different network. The ceremony still completes. **1 m of radio became an
internet hop, and nothing in the protocol noticed.**

---

## 7. Why each "fix" fails (documented dead-ends)

| Candidate | Stops replay? | Stops this relay? | Why |
|---|---|---|---|
| Nonce / challenge in advert | ✅ | ❌ | Relay forwards the live challenge |
| L2CAP CoC (this PoC) | ✅ | ❌ | Connection setup is itself relayable |
| Link + app-layer encryption | — | ❌ | Collector terminates honestly each side |
| Channel-binding BLE↔tunnel | — | ❌ | Victim legitimately holds the keys (willing party) |
| App-layer RTT over L2CAP | — | ❌ | 7.5 ms CI + jitter ≫ relay delay; see §5 readout |
| Tunnel-side secret / possession proof | — | ❌ | Possession ≠ location; phone answers honestly |
| **PHY secure ranging (CS / UWB)** | ✅ | **✅*** | Time-of-flight is the one thing a relay can't compress |

\* Ranging bounds the *radio hop* only. The collector is genuinely in the
room, so ranging must be **composed with session/token binding** or the
collector passes the range check and exfiltrates the resulting token. Stated
explicitly because it is not, to our knowledge, called out in the current
hybrid discourse.

---

## 8. Ranging coda — where a real fix attaches

The only quantities a relay provably distorts are **time-of-flight** and
**signal power**; power is attacker-set (they choose TX power), leaving
time-of-flight as the sole candidate. This is an *exhaustive* argument, not a
preference — which is why every domain with a physical-presence requirement
(EMV contactless Relay Resistance Protocol; CCC Digital Key UWB for keyless
entry) converged on timed ranging.

For Bluetooth the attach point is **Channel Sounding** (Core Spec 6.0): RTT +
phase ranging with an explicit relay / distance-shortening attacker model.
UWB (IEEE 802.15.4z) is the alternative where silicon exists. Neither is
universally present on an arbitrary phone+laptop pair, which is the real
deployment wall and the reason the Blue Steal summary calls mitigation
"structurally difficult."

**Conclusion for the paper:** the hybrid transport's proximity guarantee
cannot be repaired at the protocol/transport layer with today's commodity
hardware — only *measured around* (network endpoint-pair correlation,
phone-signed ceremony provenance as an RP-visible signal) or *replaced* at
the ranging PHY where both ends support it, composed with token binding.

---

## 9. Files

```
cable-relay-poc/
├── SPEC.md                      ← this document
├── Shared/
│   ├── Protocol.swift           ← framing + messages (both targets)
│   └── NoiseBox.swift           ← abstract Noise/AEAD stand-in (both targets)
├── iOSApp/
│   ├── App.swift                ← SwiftUI shell, role picker
│   ├── PhonePeripheral.swift    ← victim (iPhone)
│   └── CollectorCentral.swift   ← relay collector (iPad)
└── MacRelay/
    └── main.swift               ← relay-browser + RP (Mac CLI)
```

---

## 10. Scope, ethics, limits

- Research PoC on **your own devices and accounts only**. It implements no
  attack against any third party, relying party, or real caBLE deployment;
  it is a self-contained model that reproduces the *structural* property.
- `NoiseBox` is not conformant Noise and the ceremony is not CTAP2. The PoC
  deliberately models the transport property, not the FIDO payload.
- macOS/Windows lacking raw L2CAP is itself a finding worth a sentence: the
  connection-oriented primitive is only cleanly available to app developers
  via Core Bluetooth's managed CoC, which does not change the relay result.
```
