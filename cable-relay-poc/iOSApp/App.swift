//
//  App.swift
//  cable-relay-poc — iOS app shell (ONE app, two roles)
//
//  Install the SAME app on both the iPhone and the iPad, then pick the role
//  on launch: "Phone (victim)" on the iPhone, "Collector (relay)" on the iPad.
//  Keeps the demo to a single Xcode target.
//
//  Info.plist REQUIREMENTS (add these keys or iOS silently blocks BLE):
//    NSBluetoothAlwaysUsageDescription = "caBLE relay research PoC"
//    (Local networking prompt appears automatically for NWConnection on LAN;
//     if you hit it, add NSLocalNetworkUsageDescription too.)
//
//  Background note: run both apps in the FOREGROUND. Backgrounded BLE
//  peripheral/central behaviour on iOS is restricted and will complicate the
//  demo for no research benefit.
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
                Text("Pick this device's role").foregroundStyle(.secondary)
                Button("📱 Phone (victim) — run on iPhone") {
                    AxiomLog.setup(dataset: AxiomConfig.dataset, token: AxiomConfig.token, role: "phone")
                    role = .phone
                }
                    .buttonStyle(.borderedProminent)
                Button("📡 Collector (relay) — run on iPad") {
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

struct PhoneView: View {
    @StateObject private var peri = PhonePeripheral()
    var body: some View {
        VStack(alignment: .leading) {
            Text("Victim Phone").font(.title2.bold())
            Text(peri.publishedPSM == 0 ? "starting…" : "PSM \(peri.publishedPSM) · \(peri.channelOpen ? "channel open" : "advertising")")
                .foregroundStyle(.secondary)
            Divider()
            ScrollView { LogView(lines: peri.log) }
        }
        .padding()
        .onAppear { peri.start() }
    }
}

struct CollectorView: View {
    @StateObject private var central = CollectorCentral()
    @AppStorage("bridgeHost") private var host = "192.168.1.50"
    @State private var started = false
    var body: some View {
        VStack(alignment: .leading) {
            Text("Attacker Collector (Relay)").font(.title2.bold())
            HStack {
                TextField("Mac bridge IP", text: $host).textFieldStyle(.roundedBorder)
                Button("Start") {
                    central.bridgeHost = host
                    central.start(); started = true
                }.disabled(started)
            }
            Text(central.relaying ? "RELAY ACTIVE" : "idle")
                .foregroundStyle(central.relaying ? .green : .secondary)
            Divider()
            ScrollView { LogView(lines: central.log) }
        }
        .padding()
    }
}

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
