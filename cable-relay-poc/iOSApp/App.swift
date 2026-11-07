//
//  App.swift
//  cable-relay-poc — iOS app shell (ONE app, two roles)
//

import SwiftUI

@main
struct CableRelayApp: App {
    var body: some Scene { WindowGroup { RolePicker() } }
}

struct RolePicker: View {
    enum Role { case none, phone, collector }
    @State private var role: Role = .none

    var body: some View {
        switch role {
        case .none:
            VStack(spacing: 24) {
                Text("caBLE Relay PoC").font(.largeTitle.bold())
                Text("PXP-aligned: NKpsk0 / P-256 / AES-GCM").font(.caption).foregroundStyle(.secondary)
                Text("Pick this device's role").foregroundStyle(.secondary)
                Button("Phone (victim) — run on iPhone") {
                    AxiomLog.setup(dataset: AxiomConfig.dataset, token: AxiomConfig.token, role: "phone")
                    role = .phone
                }
                    .buttonStyle(.borderedProminent)
                Button("Collector (relay) — run on iPad") {
                    AxiomLog.setup(dataset: AxiomConfig.dataset, token: AxiomConfig.token, role: "collector")
                    role = .collector
                }
                    .buttonStyle(.bordered)
            }.padding()
        case .phone:
            PhoneView()
        case .collector:
            CollectorView()
        }
    }
}

// MARK: - Phone View

struct PhoneView: View {
    @StateObject private var peri = PhonePeripheral()

    var body: some View {
        VStack(spacing: 0) {
            PhoneStatusBanner(state: peri.ceremonyState)

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Victim Phone").font(.title2.bold())
                    Spacer()
                    if peri.ceremonyState == .signed || peri.ceremonyState != .idle {
                        Button("Retest") { peri.retest() }
                            .buttonStyle(.bordered)
                            .tint(.orange)
                    }
                }

                Text(statusText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Divider()
                ScrollViewReader { proxy in
                    ScrollView {
                        LogView(lines: peri.log)
                            .id("log-bottom")
                    }
                    .onChange(of: peri.log.count) { _ in
                        withAnimation { proxy.scrollTo("log-bottom", anchor: .bottom) }
                    }
                }
            }
            .padding()
        }
        .onAppear { peri.start() }
    }

    private var statusText: String {
        switch peri.ceremonyState {
        case .idle: return "Starting..."
        case .advertising: return "PSM \(peri.publishedPSM) — advertising, waiting for relay"
        case .channelConnected: return "L2CAP connected — awaiting handshake"
        case .handshakeComplete: return "NKpsk0 handshake complete — awaiting assertion"
        case .signed: return "Assertion SIGNED — ceremony complete"
        case .failed(let msg): return "FAILED: \(msg)"
        }
    }
}

struct PhoneStatusBanner: View {
    let state: PhonePeripheral.CeremonyState

    var body: some View {
        switch state {
        case .signed:
            banner(color: .red, icon: "exclamationmark.triangle.fill",
                   title: "RELAY ATTACK SUCCEEDED",
                   subtitle: "You signed a session you never initiated")
        case .handshakeComplete:
            banner(color: .orange, icon: "lock.fill",
                   title: "NKpsk0 Session Established",
                   subtitle: "P-256 / AES-256-GCM / SHA-256")
        case .channelConnected:
            banner(color: .blue, icon: "antenna.radiowaves.left.and.right",
                   title: "L2CAP Connected",
                   subtitle: "Insecure CoC — waiting for handshake")
        case .failed(let msg):
            banner(color: .gray, icon: "xmark.circle.fill",
                   title: "Failed", subtitle: msg)
        default:
            EmptyView()
        }
    }

    private func banner(color: Color, icon: String, title: String, subtitle: String) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.title)
            Text(title).font(.headline.bold())
            Text(subtitle).font(.caption)
        }
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity)
        .padding()
        .background(color)
    }
}

// MARK: - Collector View

struct CollectorView: View {
    @StateObject private var central = CollectorCentral()
    @AppStorage("bridgeHost") private var host = "192.168.1.50"
    @State private var started = false

    var body: some View {
        VStack(spacing: 0) {
            CollectorStatusBanner(state: central.ceremonyState, frames: central.framesRelayed)

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Attacker Collector").font(.title2.bold())
                    Spacer()
                    if started {
                        Button("Retest") {
                            central.retest()
                        }
                        .buttonStyle(.bordered)
                        .tint(.orange)
                    }
                }

                HStack {
                    TextField("Mac bridge IP", text: $host).textFieldStyle(.roundedBorder)
                    Button("Start") {
                        central.bridgeHost = host
                        central.start(); started = true
                    }.disabled(started)
                }

                HStack {
                    Text(statusText)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Spacer()
                    if central.framesRelayed > 0 {
                        Text("\(central.framesRelayed) frames")
                            .font(.caption.monospacedDigit())
                            .padding(.horizontal, 8)
                            .padding(.vertical, 2)
                            .background(.quaternary)
                            .clipShape(Capsule())
                    }
                }

                Divider()
                ScrollViewReader { proxy in
                    ScrollView {
                        LogView(lines: central.log)
                            .id("log-bottom")
                    }
                    .onChange(of: central.log.count) { _ in
                        withAnimation { proxy.scrollTo("log-bottom", anchor: .bottom) }
                    }
                }
            }
            .padding()
        }
    }

    private var statusText: String {
        switch central.ceremonyState {
        case .idle: return "Idle"
        case .scanning: return "Scanning for victim phone..."
        case .bleConnected: return "BLE connected — reading PSM"
        case .l2capOpen: return "L2CAP open — waiting for TCP"
        case .relayActive: return "RELAY ACTIVE — forwarding frames"
        case .ceremonyComplete: return "Ceremony relayed successfully"
        case .failed(let msg): return "FAILED: \(msg)"
        }
    }
}

struct CollectorStatusBanner: View {
    let state: CollectorCentral.CeremonyState
    let frames: Int

    var body: some View {
        switch state {
        case .ceremonyComplete:
            banner(color: .red, icon: "checkmark.shield.fill",
                   title: "RELAY COMPLETE",
                   subtitle: "\(frames) frames relayed — no crypto broken")
        case .relayActive:
            banner(color: .green, icon: "arrow.left.arrow.right",
                   title: "Relay Active",
                   subtitle: "Phone <-> iPad (BLE) <-> Mac (TCP)")
        case .scanning:
            banner(color: .blue, icon: "magnifyingglass",
                   title: "Scanning",
                   subtitle: "Looking for victim phone BLE advert")
        case .failed(let msg):
            banner(color: .gray, icon: "xmark.circle.fill",
                   title: "Failed", subtitle: msg)
        default:
            EmptyView()
        }
    }

    private func banner(color: Color, icon: String, title: String, subtitle: String) -> some View {
        VStack(spacing: 4) {
            Image(systemName: icon).font(.title)
            Text(title).font(.headline.bold())
            Text(subtitle).font(.caption)
        }
        .foregroundStyle(.white)
        .frame(maxWidth: .infinity)
        .padding()
        .background(color)
    }
}

// MARK: - Shared

struct LogView: View {
    let lines: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                Text(l).font(.system(.caption, design: .monospaced))
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
