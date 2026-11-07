//
//  AxiomLog.swift
//  cable-relay-poc — Lightweight Axiom ingest logger
//
//  Ships log lines to Axiom's Events Ingest API as JSON. Batches events
//  and flushes periodically or when the buffer hits a threshold.
//  Works on both iOS (URLSession) and macOS (URLSession).
//
//  No dependencies beyond Foundation.
//

import Foundation
#if canImport(UIKit)
import UIKit
#endif

final class AxiomLog {
    static var shared: AxiomLog?

    private let dataset: String
    private let token: String
    private let role: String
    private let deviceName: String
    private let session: URLSession
    private var buffer: [[String: Any]] = []
    private let lock = NSLock()
    private var flushTimer: Timer?

    init(dataset: String, token: String, role: String, deviceName: String = "") {
        self.dataset = dataset
        self.token = token
        self.role = role
        self.deviceName = deviceName.isEmpty ? Self.hostName() : deviceName
        self.session = URLSession(configuration: .default)
        startFlushTimer()
    }

    static func setup(dataset: String, token: String, role: String, deviceName: String = "") {
        shared = AxiomLog(dataset: dataset, token: token, role: role, deviceName: deviceName)
    }

    func log(_ message: String) {
        let event: [String: Any] = [
            "_time": ISO8601DateFormatter().string(from: Date()),
            "source": "cable-relay-poc",
            "role": role,
            "device": deviceName,
            "message": message
        ]
        lock.lock()
        buffer.append(event)
        let count = buffer.count
        lock.unlock()

        if count >= 10 { flush() }
    }

    func flush() {
        lock.lock()
        guard !buffer.isEmpty else { lock.unlock(); return }
        let batch = buffer
        buffer.removeAll()
        lock.unlock()

        guard let url = URL(string: "https://api.axiom.co/v1/datasets/\(dataset)/ingest") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: batch)

        session.dataTask(with: req) { _, resp, err in
            if let err {
                NSLog("[AXIOM] flush error: %@", err.localizedDescription)
            } else if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
                NSLog("[AXIOM] flush HTTP %d", http.statusCode)
            }
        }.resume()
    }

    private func startFlushTimer() {
        DispatchQueue.main.async {
            self.flushTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
                self?.flush()
            }
        }
    }

    private static func hostName() -> String {
        #if os(iOS)
        return UIDevice.current.name
        #else
        return Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        #endif
    }
}
