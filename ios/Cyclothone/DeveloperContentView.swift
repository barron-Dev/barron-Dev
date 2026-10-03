import SwiftUI
import Foundation

struct DeveloperContentView: View {
    @StateObject private var auth = AuthStore()

    var body: some View {
        Group {
            if auth.authenticated {
                DeveloperPortalView(auth: auth)
            } else {
                DeveloperSignInView(auth: auth)
            }
        }
        .preferredColorScheme(.dark)
    }
}

private struct DeveloperSignInView: View {
    @ObservedObject var auth: AuthStore

    var body: some View {
        VStack(spacing: 18) {
            Text("CYCLOTHONE").font(.system(size: 28, weight: .bold))
            Text("Developer access").foregroundStyle(.secondary)
            Text(auth.message).font(.footnote).multilineTextAlignment(.center)
            Button("Sign in with Google") { auth.signIn(provider: "google") }
                .buttonStyle(.borderedProminent)
            Button("Continue with GitHub") { auth.signIn(provider: "github") }
                .buttonStyle(.bordered)
            Button("Email / Magic link") {
                // Developer access uses the same verified identity session as the customer app.
                auth.message = "Use the secure sign-in options above."
            }
            .buttonStyle(.bordered)
        }
        .padding(28)
        .frame(maxWidth: 520)
    }
}

private struct DeveloperPortalView: View {
    @ObservedObject var auth: AuthStore
    @StateObject private var model = DeveloperPortalModel()

    var body: some View {
        portalContent
    }

    @ViewBuilder
    private var portalContent: some View {
        NavigationStack {
            List {
                developerSection
                applicationsSection
                credentialsSection
                mobileIntelligenceSection
                accountSection
            }
            .navigationTitle("Developer")
            .task { await model.load(token: auth.accessToken) }
            .alert("Create application", isPresented: $model.showCreate) {
                TextField("Application name", text: $model.newAppName)
                Button("Create") {
                    Task { await model.createApp(token: auth.accessToken) }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The application is created through the live Developer API.")
            }
            .alert("Issue API credential", isPresented: $model.showIssueKey) {
                TextField("Scopes (comma separated)", text: $model.newScopes)
                Button("Issue") {
                    Task { await model.issueKey(token: auth.accessToken) }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("The credential secret is returned once by the live API.")
            }
            .sheet(isPresented: Binding(
                get: { model.issuedSecret != nil },
                set: { if !$0 { model.issuedSecret = nil } }
            )) {
                IssuedSecretView(secret: model.issuedSecret ?? "") {
                    model.issuedSecret = nil
                }
            }
            .alert("Developer error", isPresented: Binding(
                get: { model.error != nil },
                set: { if !$0 { model.error = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(model.error ?? "")
            }
        }
    }

    @ViewBuilder
    private var developerSection: some View {
        Section("Developer") {
            Text("Applications and API credentials")
                .font(.headline)
            Text("Manage real developer applications and credentials through the Cyclothone API. Secrets are shown only when issued.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Refresh") {
                Task { await model.load(token: auth.accessToken) }
            }
        }
    }

    @ViewBuilder
    private var applicationsSection: some View {
        Section("Applications") {
            if model.apps.isEmpty {
                Text(model.loading ? "Loading…" : "No applications found.")
                    .foregroundStyle(.secondary)
            }
            ForEach(model.apps) { app in
                ApplicationRow(
                    app: app,
                    selected: model.selectedApp?.id == app.id
                ) {
                    model.select(app)
                    Task { await model.loadKeys(token: auth.accessToken) }
                }
            }
            Button("Create application") {
                model.showCreate = true
            }
        }
    }

    @ViewBuilder
    private var credentialsSection: some View {
        if let app = model.selectedApp {
            Section("API credentials") {
                Text(app.name)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if model.keys.isEmpty {
                    Text("No credentials found.")
                        .foregroundStyle(.secondary)
                }
                ForEach(model.keys) { key in
                    DeveloperKeyRow(key: key)
                }
                Button("Issue API credential") {
                    model.showIssueKey = true
                }
            }
        }
    }

    @ViewBuilder
    private var mobileIntelligenceSection: some View {
        Section("Mobile Intelligence") {
            Text("Requests use the real Mobile Intelligence API and require the approved mobile:intelligence authority. Provider data is never fabricated.")
                .font(.caption)
                .foregroundStyle(.secondary)
            NavigationLink("Query Mobile Intelligence") {
                MobileIntelligenceView(auth: auth)
            }
        }
    }

    @ViewBuilder
    private var accountSection: some View {
        Section {
            Button("Sign out") {
                model.reset()
                auth.signOut()
            }
        }
    }
}

private struct ApplicationRow: View {
    let app: DeveloperApp
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(app.name)
                    Text(app.active ? "Active" : "Inactive")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if selected {
                    Image(systemName: "checkmark")
                }
            }
        }
    }
}

private struct IssuedSecretView: View {
    let secret: String
    let dismiss: () -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 16) {
                Text("API credential issued")
                    .font(.headline)
                Text("This secret is shown only from the issuance response. Copy or record it now; it will not be stored in the credential list.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(secret)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                Spacer()
                Button("Done") {
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
            .navigationTitle("New API secret")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

private struct DeveloperKeyRow: View {
    let key: DeveloperKey

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(key.key_prefix)
            Text(key.active ? "Active" : "Inactive")
                .font(.caption2)
                .foregroundStyle(.secondary)
            Text(key.scopes.joined(separator: ", "))
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

private struct MobileIntelligenceView: View {
    @ObservedObject var auth: AuthStore
    @State private var query = ""
    @State private var result: String?
    @State private var error: String?
    @State private var running = false

    var body: some View {
        Form {
            Section("Query") {
                TextField("Approved intelligence query", text: $query, axis: .vertical)
                Button(running ? "Running…" : "Run live query") {
                    Task { await run() }
                }
                .disabled(running || query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            if let result {
                Section("Result") {
                    Text(result)
                        .textSelection(.enabled)
                }
            }
            if let error {
                Section("Error") {
                    Text(error).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Mobile Intelligence")
    }

    private func run() async {
        guard let token = auth.accessToken else { error = "Authentication session is missing."; return }
        running = true
        defer { running = false }
        do {
            result = try await DeveloperAPI.mobileIntelligence(query: query, token: token)
            error = nil
        } catch {
            result = nil
            self.error = error.localizedDescription
        }
    }
}

@MainActor
private final class DeveloperPortalModel: ObservableObject {
    @Published var apps: [DeveloperApp] = []
    @Published var keys: [DeveloperKey] = []
    @Published var selectedApp: DeveloperApp?
    @Published var loading = false
    @Published var error: String?
    @Published var showCreate = false
    @Published var showIssueKey = false
    @Published var newAppName = ""
    @Published var newScopes = ""
    @Published var issuedSecret: String?

    func load(token: String?) async {
        guard let token, !token.isEmpty else { error = "Authentication session is missing."; return }
        loading = true
        defer { loading = false }
        do {
            apps = try await DeveloperAPI.apps(token: token)
            if let selectedApp, let refreshed = apps.first(where: { $0.id == selectedApp.id }) {
                self.selectedApp = refreshed
                keys = try await DeveloperAPI.keys(appID: refreshed.id, token: token)
            } else {
                keys = []
            }
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func select(_ app: DeveloperApp) {
        selectedApp = app
        keys = []
    }

    func loadKeys(token: String?) async {
        guard let token, let selectedApp else { return }
        do {
            keys = try await DeveloperAPI.keys(appID: selectedApp.id, token: token)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func createApp(token: String?) async {
        guard let token, !newAppName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            error = "Application name is required."
            return
        }
        do {
            let scopes = newScopes.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            let app = try await DeveloperAPI.createApp(name: newAppName, scopes: scopes, token: token)
            newAppName = ""
            newScopes = ""
            apps.append(app)
            selectedApp = app
            keys = []
            showCreate = false
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func issueKey(token: String?) async {
        guard let token, let selectedApp else { return }
        do {
            let response = try await DeveloperAPI.issueKey(
                appID: selectedApp.id,
                scopes: newScopes.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty },
                token: token
            )
            guard let secret = response.api_key ?? response.key, !secret.isEmpty else {
                throw DeveloperAPIError.missingIssuedSecret
            }
            issuedSecret = secret
            newScopes = ""
            showIssueKey = false
            keys = try await DeveloperAPI.keys(appID: selectedApp.id, token: token)
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func reset() {
        issuedSecret = nil
        apps = []
        keys = []
        selectedApp = nil
    }
}

private struct DeveloperApp: Decodable, Identifiable, Hashable {
    let id: String
    let name: String
    let description: String?
    let active: Bool
    let created_at: String
}

private struct DeveloperKey: Decodable, Identifiable, Hashable {
    let id: String
    let app_id: String
    let key_prefix: String
    let scopes: [String]
    let active: Bool
    let expires_at: String?
    let created_at: String
}

private struct DeveloperKeyIssueResponse: Decodable {
    let api_key: String?
    let key: String?
}

private enum DeveloperAPI {
    static let base = URL(string: "https://cyclothone-api-production.up.railway.app")!

    static func apps(token: String) async throws -> [DeveloperApp] {
        try await request("/api/v1/developer/apps", method: "GET", body: nil, token: token)
    }

    static func createApp(name: String, scopes: [String], token: String) async throws -> DeveloperApp {
        try await request("/api/v1/developer/apps", method: "POST", body: [
            "name": name,
            "allowed_scopes": scopes
        ], token: token)
    }

    static func keys(appID: String, token: String) async throws -> [DeveloperKey] {
        try await request("/api/v1/developer/apps/\(appID)/keys", method: "GET", body: nil, token: token)
    }

    static func issueKey(appID: String, scopes: [String], token: String) async throws -> DeveloperKeyIssueResponse {
        try await request("/api/v1/developer/apps/\(appID)/keys", method: "POST", body: [
            "scopes": scopes
        ], token: token)
    }

    static func mobileIntelligence(query: String, token: String) async throws -> String {
        let data: Data = try await requestData("/api/v1/mobile-intelligence/query", method: "POST", body: [
            "query": query
        ], token: token)
        return String(data: data, encoding: .utf8) ?? "Live API returned a non-text response."
    }

    private static func request<T: Decodable>(_ path: String, method: String, body: [String: Any]?, token: String) async throws -> T {
        let data = try await requestData(path, method: method, body: body, token: token)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private static func requestData(_ path: String, method: String, body: [String: Any]?, token: String) async throws -> Data {
        var request = URLRequest(url: base.appendingPathComponent(path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))))
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw DeveloperAPIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            throw DeveloperAPIError.server(http.statusCode, message: Self.message(data))
        }
        return data
    }

    private static func message(_ data: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return (object["message"] as? String) ?? (object["detail"] as? String) ?? (object["error"] as? String)
    }
}

private enum DeveloperAPIError: LocalizedError {
    case invalidResponse
    case missingIssuedSecret
    case server(Int, message: String?)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Developer API returned an invalid response."
        case .missingIssuedSecret:
            return "The Developer API did not return the one-time API secret."
        case .server(let code, let message):
            return message ?? "Developer API returned HTTP \(code)."
        }
    }
}
