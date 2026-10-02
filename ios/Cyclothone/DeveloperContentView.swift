import SwiftUI

struct DeveloperContentView: View {
    @StateObject private var auth = AuthStore()
    @StateObject private var model = DeveloperModel()

    var body: some View {
        Group {
            if auth.authenticated {
                DeveloperWorkspace(auth: auth, model: model)
            } else {
                DeveloperSignIn(auth: auth)
            }
        }
        .preferredColorScheme(.dark)
    }
}

private struct DeveloperSignIn: View {
    @ObservedObject var auth: AuthStore
    @State private var email = ""
    @State private var password = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Cyclothone Developer") {
                    Text("Secure access to your provisioned developer account.")
                    Text(auth.message).font(.caption).foregroundStyle(.secondary)
                }
                Section("Sign in") {
                    TextField("Email", text: $email).textInputAutocapitalization(.never).keyboardType(.emailAddress)
                    SecureField("Password", text: $password)
                    Button("Sign in") {
                        Task { await auth.passwordSignIn(email: email, password: password) }
                    }
                    Button("Sign in with Google") { auth.signIn(provider: "google") }
                    Button("Continue with GitHub") { auth.signIn(provider: "github") }
                }
            }
            .navigationTitle("Developer")
        }
    }
}

struct DeveloperWorkspace: View {
    @ObservedObject var auth: AuthStore
    @ObservedObject var model: DeveloperModel
    @State private var showingCreate = false
    @State private var selected: DeveloperAppRecord?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        VStack(alignment: .leading) {
                            Text("Developer portal").font(.headline)
                            Text(model.identity.map { "Tenant \($0.tenantID)" } ?? "Checking developer access…")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Circle().fill(model.provisioned ? Color.green : Color.orange).frame(width: 9, height: 9)
                    }
                }

                if !model.provisioned {
                    Section {
                        Text("Developer access is not provisioned for this account.")
                            .foregroundStyle(.orange)
                    }
                }

                Section("Applications") {
                    if model.apps.isEmpty {
                        Text("No developer applications exist in the live account.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.apps) { app in
                        Button { selected = app } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(app.name).font(.headline)
                                Text(app.active ? "Active" : "Inactive")
                                    .font(.caption)
                                    .foregroundStyle(app.active ? .green : .secondary)
                                Text(app.description ?? "No description")
                                    .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Cyclothone Developer")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Sign out") { auth.signOut(); model.reset() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("New app") { showingCreate = true }.disabled(!model.provisioned)
                }
            }
            .refreshable { await model.refresh(token: auth.accessToken) }
            .task { await model.refresh(token: auth.accessToken) }
            .sheet(isPresented: $showingCreate) {
                CreateAppView(model: model, token: auth.accessToken)
            }
            .sheet(item: $selected) { app in
                DeveloperAppDetailView(model: model, token: auth.accessToken, app: app)
            }
            .alert("Developer API", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
                Button("OK") { error = nil }
            } message: {
                Text(error ?? "")
            }
        }
    }
}

private struct CreateAppView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: DeveloperModel
    let token: String?
    @State private var name = ""
    @State private var description = ""
    @State private var scopes = ""
    @State private var redirects = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Application") {
                    TextField("Name", text: $name)
                    TextField("Description", text: $description, axis: .vertical)
                }
                Section("OAuth/API policy") {
                    TextField("Allowed scopes (comma separated)", text: $scopes, axis: .vertical)
                    TextField("Redirect URIs (one per line)", text: $redirects, axis: .vertical)
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
            .navigationTitle("New developer app")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        Task {
                            do {
                                try await model.createApp(
                                    token: token,
                                    name: name,
                                    description: description,
                                    scopes: DeveloperModel.splitList(scopes),
                                    redirects: DeveloperModel.splitLines(redirects)
                                )
                                dismiss()
                            } catch { error = error.localizedDescription }
                        }
                    }.disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
    }
}

private struct DeveloperAppDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var model: DeveloperModel
    let token: String?
    let app: DeveloperAppRecord
    @State private var scopeText = ""
    @State private var expiresAt = ""
    @State private var publicClient = false
    @State private var secret: String?
    @State private var clientID: String?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section("Application") {
                    LabeledContent("Name", value: app.name)
                    LabeledContent("Status", value: app.active ? "Active" : "Inactive")
                    LabeledContent("Scopes", value: app.allowedScopes.joined(separator: ", ").isEmpty ? "None" : app.allowedScopes.joined(separator: ", "))
                    LabeledContent("Redirect URIs", value: app.redirectURIs.joined(separator: ", ").isEmpty ? "None" : app.redirectURIs.joined(separator: ", "))
                }
                Section("API keys") {
                    TextField("Scopes for new key", text: $scopeText)
                    TextField("Expires at (ISO 8601, optional)", text: $expiresAt)
                    Button("Issue API key") {
                        Task {
                            do {
                                let result = try await model.issueKey(token: token, appID: app.id, scopes: DeveloperModel.splitList(scopeText), expiresAt: expiresAt)
                                secret = result.key
                            } catch { error = error.localizedDescription }
                        }
                    }.disabled(!app.active)
                    ForEach(model.keys[app.id] ?? []) { key in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(key.keyPrefix)
                                Text(key.active ? "Active" : "Revoked").font(.caption).foregroundStyle(key.active ? .green : .secondary)
                            }
                            Spacer()
                            if key.active {
                                Button("Revoke") {
                                    Task { do { try await model.revokeKey(token: token, appID: app.id, keyID: key.id) } catch { error = error.localizedDescription } }
                                }
                            }
                        }
                    }
                }
                Section("OAuth clients") {
                    Toggle("Public client", isOn: $publicClient)
                    Button("Create OAuth client") {
                        Task {
                            do {
                                let result = try await model.createOAuthClient(token: token, appID: app.id, publicClient: publicClient)
                                clientID = result.clientID
                                secret = result.secret
                            } catch { error = error.localizedDescription }
                        }
                    }
                    ForEach(model.oauthClients[app.id] ?? []) { client in
                        HStack {
                            Text(client.clientID).font(.caption)
                            Spacer()
                            if client.active {
                                Button("Deactivate") {
                                    Task { do { try await model.deactivateOAuthClient(token: token, appID: app.id, clientID: client.id) } catch { error = error.localizedDescription } }
                            }
                        }
                    }
                }
                if let clientID {
                    Section("New OAuth client") {
                        Text("Client ID").font(.caption)
                        Text(clientID).textSelection(.enabled).font(.body.monospaced())
                        if let secret {
                            Text("Client secret — shown once").font(.caption).foregroundStyle(.orange)
                            Text(secret).textSelection(.enabled).font(.body.monospaced())
                        }
                    }
                } else if let secret {
                    Section("New secret — shown once") {
                        Text(secret).textSelection(.enabled).font(.body.monospaced())
                    }
                }
                if let error { Section { Text(error).foregroundStyle(.red) } }
            }
            .navigationTitle(app.name)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .task { await model.loadAppSecurity(token: token, appID: app.id) }
        }
    }
}

@MainActor
final class DeveloperModel: ObservableObject {
    @Published private(set) var identity: DeveloperIdentity?
    @Published private(set) var provisioned = false
    @Published private(set) var apps: [DeveloperAppRecord] = []
    @Published private(set) var keys: [String: [DeveloperKey]] = [:]
    @Published private(set) var oauthClients: [String: [DeveloperOAuthClient]] = [:]

    func reset() {
        identity = nil; provisioned = false; apps = []; keys = [:]; oauthClients = [:]
    }

    func refresh(token: String?) async {
        guard let token, !token.isEmpty else { return }
        do {
            identity = try await DeveloperAPI.get("/api/v1/developer/me", token: token)
            provisioned = true
            apps = try await DeveloperAPI.get("/api/v1/developer/apps", token: token)
        } catch {
            provisioned = false
            apps = []
        }
    }

    func createApp(token: String?, name: String, description: String, scopes: [String], redirects: [String]) async throws {
        guard let token else { throw DeveloperAPIError.auth }
        _ = try await DeveloperAPI.post("/api/v1/developer/apps", token: token, body: [
            "name": name,
            "description": description.isEmpty ? NSNull() : description,
            "allowed_scopes": scopes,
            "redirect_uris": redirects
        ])
        apps = try await DeveloperAPI.get("/api/v1/developer/apps", token: token)
    }

    func loadAppSecurity(token: String?, appID: String) async {
        guard let token else { return }
        do {
            async let k: [DeveloperKey] = DeveloperAPI.get("/api/v1/developer/apps/\(appID)/keys", token: token)
            async let o: [DeveloperOAuthClient] = DeveloperAPI.get("/api/v1/developer/apps/\(appID)/oauth-clients", token: token)
            keys[appID] = try await k
            oauthClients[appID] = try await o
        } catch { }
    }

    func issueKey(token: String?, appID: String, scopes: [String], expiresAt: String) async throws -> DeveloperKeyIssue {
        guard let token else { throw DeveloperAPIError.auth }
        let result: DeveloperKeyIssue = try await DeveloperAPI.post("/api/v1/developer/apps/\(appID)/keys", token: token, body: [
            "scopes": scopes,
            "expires_at": expiresAt.isEmpty ? NSNull() : expiresAt
        ])
        await loadAppSecurity(token: token, appID: appID)
        return result
    }

    func revokeKey(token: String?, appID: String, keyID: String) async throws {
        guard let token else { throw DeveloperAPIError.auth }
        let _: EmptyResponse = try await DeveloperAPI.post("/api/v1/developer/apps/\(appID)/keys/\(keyID)/revoke", token: token, body: [:])
        await loadAppSecurity(token: token, appID: appID)
    }

    func createOAuthClient(token: String?, appID: String, publicClient: Bool) async throws -> OAuthClientIssue {
        guard let token else { throw DeveloperAPIError.auth }
        let result: OAuthClientIssue = try await DeveloperAPI.post("/api/v1/developer/apps/\(appID)/oauth-clients", token: token, body: ["public_client": publicClient])
        await loadAppSecurity(token: token, appID: appID)
        return result
    }

    func deactivateOAuthClient(token: String?, appID: String, clientID: String) async throws {
        guard let token else { throw DeveloperAPIError.auth }
        let _: EmptyResponse = try await DeveloperAPI.post("/api/v1/developer/apps/\(appID)/oauth-clients/\(clientID)/deactivate", token: token, body: [:])
        await loadAppSecurity(token: token, appID: appID)
    }

    static func splitList(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
    static func splitLines(_ value: String) -> [String] {
        value.split(whereSeparator: \\.isNewline).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

struct DeveloperIdentity: Decodable {
    let userID: String
    let tenantID: String
    enum CodingKeys: String, CodingKey { case userID = "user_id"; case tenantID = "tenant_id" }
}
struct DeveloperAppRecord: Decodable, Identifiable, Hashable {
    let id: String; let tenantID: String; let ownerUserID: String; let name: String; let description: String?
    let active: Bool; let allowedScopes: [String]; let redirectURIs: [String]; let createdAt: String; let updatedAt: String
    enum CodingKeys: String, CodingKey {
        case id, tenantID = "tenant_id", ownerUserID = "owner_user_id", name, description, active, allowedScopes = "allowed_scopes", redirectURIs = "redirect_uris", createdAt = "created_at", updatedAt = "updated_at"
    }
}
struct DeveloperKey: Decodable, Identifiable {
    let id: String; let appID: String; let keyPrefix: String; let scopes: [String]; let active: Bool; let expiresAt: String?; let lastUsedAt: String?; let createdAt: String; let revokedAt: String?
    enum CodingKeys: String, CodingKey { case id, appID = "app_id", keyPrefix = "key_prefix", scopes, active, expiresAt = "expires_at", lastUsedAt = "last_used_at", createdAt = "created_at", revokedAt = "revoked_at" }
}
struct DeveloperOAuthClient: Decodable, Identifiable {
    let id: String; let appID: String; let clientID: String; let publicClient: Bool; let active: Bool; let createdAt: String; let lastUsedAt: String?
    enum CodingKeys: String, CodingKey { case id, appID = "app_id", clientID = "client_id", publicClient = "public_client", active, createdAt = "created_at", lastUsedAt = "last_used_at" }
}
struct DeveloperKeyIssue: Decodable { let key: String }
struct OAuthClientIssue: Decodable { let id: String; let appID: String; let clientID: String; let publicClient: Bool; let clientSecret: String?
    enum CodingKeys: String, CodingKey { case id, appID = "app_id", clientID = "client_id", publicClient = "public_client", clientSecret = "client_secret" }
}
struct EmptyResponse: Decodable {}

private enum DeveloperAPI {
    static let base = URL(string: "https://cyclothone-api-production.up.railway.app")!

    static func get<T: Decodable>(_ path: String, token: String) async throws -> T {
        try await request(path, token: token, method: "GET", body: nil)
    }

    static func post<T: Decodable>(_ path: String, token: String, body: [String: Any]) async throws -> T {
        let data = try JSONSerialization.data(withJSONObject: body)
        return try await request(path, token: token, method: "POST", body: data)
    }

    private static func request<T: Decodable>(_ path: String, token: String, method: String, body: Data?) async throws -> T {
        var request = URLRequest(url: base.appendingPathComponent(path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))))
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.httpBody = body
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw DeveloperAPIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 { throw DeveloperAPIError.auth }
            if http.statusCode == 403 { throw DeveloperAPIError.forbidden }
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["detail"] as? String
            throw DeveloperAPIError.server(http.statusCode, message ?? "Developer API request failed.")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}

private enum DeveloperAPIError: LocalizedError {
    case auth, forbidden, invalidResponse, server(Int, String)
    var errorDescription: String? {
        switch self {
        case .auth: return "Authentication session is missing or expired."
        case .forbidden: return "Developer access is not provisioned for this account."
        case .invalidResponse: return "Developer API returned an invalid response."
        case .server(let code, let message): return "Developer API HTTP \(code): \(message)"
        }
    }
}
