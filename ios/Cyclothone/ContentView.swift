import SwiftUI
import Foundation
import WebKit
import UserNotifications
import CryptoKit
import UIKit

struct ContentView: View {
    @StateObject private var auth = AuthStore()
    @State private var mode: Mode = .entry
    @State private var email = ""; @State private var password = ""; @State private var name = ""; @State private var phone = ""

    enum Mode { case entry, password, magic, register }

    var body: some View {
        Group {
            if auth.authenticated {
                MobileWorkspace(auth: auth)
            } else {
                form
            }
        }
        .preferredColorScheme(.dark)
        .onOpenURL { url in
            if url.scheme == "cyclothone-ios" { auth.message = "Finishing secure sign-in…" }
        }
    }

    @ViewBuilder private var form: some View {
        ZStack {
            Color(red:0.016,green:0.063,blue:0.106).ignoresSafeArea()
            ScrollView {
                VStack(spacing:16) {
                    Text("CYCLOTHONE").font(.system(size:28,weight:.bold))
                    Text("Secure mobile access").foregroundStyle(.secondary)
                    Text(auth.message).font(.footnote).multilineTextAlignment(.center).padding(.bottom,8)
                    switch mode {
                    case .entry:
                        Button("Sign in with Google") { auth.signIn(provider:"google") }.buttonStyle(.borderedProminent)
                        Button("Continue with GitHub") { auth.signIn(provider:"github") }.buttonStyle(.bordered)
                        Button("Email / Magic link") { mode = .magic }.buttonStyle(.bordered)
                        Button("Create account / Registration") { mode = .register }.buttonStyle(.bordered)
                        Button("Email + Password") { mode = .password }.buttonStyle(.bordered)
                    case .password:
                        fields(title:"Email + Password", submit:"Sign in") { Task { await auth.passwordSignIn(email:email,password:password) } }
                    case .magic:
                        fields(title:"Email sign-in", submit:"Send secure link", passwordField:false) { Task { await auth.sendMagicLink(email:email) } }
                    case .register:
                        fields(title:"Create Cyclothone account", submit:"Create account", includeName:true, includePhone:true) { Task { await auth.register(name:name,email:email,phone:phone,password:password) } }
                    }
                    if mode != .entry { Button("Back") { mode = .entry } }
                }.padding(28).frame(maxWidth:560)
            }
        }
    }

    @ViewBuilder private func fields(title:String,submit:String,passwordField:Bool=true,includeName:Bool=false,includePhone:Bool=false,action:@escaping()->Void)->some View {
        Text(title).font(.title2.bold())
        if includeName { TextField("Name or company name",text:$name).textContentType(.name).textFieldStyle(.roundedBorder) }
        TextField("Email",text:$email).textInputAutocapitalization(.never).keyboardType(.emailAddress).textFieldStyle(.roundedBorder)
        if includePhone { TextField("Phone",text:$phone).keyboardType(.phonePad).textFieldStyle(.roundedBorder) }
        if passwordField { SecureField("Password",text:$password).textFieldStyle(.roundedBorder) }
        Button(submit,action:action).buttonStyle(.borderedProminent)
    }
}

struct MobileWorkspace: View {
    @ObservedObject var auth: AuthStore
    @StateObject private var model = MobileWorkspaceModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment:.leading, spacing:16) {
                    HStack {
                        VStack(alignment:.leading, spacing:4) {
                            Text("CYCLOTHONE").font(.headline)
                            Text("Mobile workspace").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Circle().fill(model.isFresh ? Color.green : Color.orange).frame(width:9,height:9)
                        Text(model.lastUpdated.map(Self.timeText) ?? "Syncing").font(.caption2).foregroundStyle(.secondary)
                    }

                    if let error = model.error {
                        Text(error).font(.caption).foregroundStyle(.red).padding(10).frame(maxWidth:.infinity,alignment:.leading).background(.red.opacity(0.08)).clipShape(RoundedRectangle(cornerRadius:12))
                    }

                    if let notice = model.notice {
                        HStack(spacing:10) {
                            Image(systemName:"bell.fill")
                            Text(notice).font(.caption)
                        }.padding(12).frame(maxWidth:.infinity,alignment:.leading).background(.orange.opacity(0.10)).clipShape(RoundedRectangle(cornerRadius:12))
                    }

                    SectionCard(title:"Workspace", value:model.organizationName ?? "Loading…", detail:model.admissionStatus ?? "Live account state") {
                        Button("Open full workspace") { UIApplication.shared.open(auth.openWorkspaceURL()) }
                            .buttonStyle(.borderedProminent)
                    }

                    HStack(spacing:10) {
                        MetricCard(title:"Requests", value:"\(model.requests.count)")
                        MetricCard(title:"Active", value:"\(model.activeRequests)")
                        MetricCard(title:"Cases", value:"\(model.cases.count)")
                    }

                    VStack(alignment:.leading, spacing:10) {
                        Text("Security services").font(.headline)
                        Text("All service workflows remain available through the same customer workspace. This mobile view is the fast operational surface; it does not create a reduced service set.")
                            .font(.caption).foregroundStyle(.secondary)
                        ForEach(MobileService.all) { service in
                            Button { UIApplication.shared.open(service.url) } label: {
                                HStack {
                                    Image(systemName:service.icon).frame(width:24)
                                    VStack(alignment:.leading) {
                                        Text(service.name).font(.subheadline)
                                        Text("Open live workspace").font(.caption2).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName:"chevron.right").font(.caption)
                                }
                                .padding(12)
                                .background(.white.opacity(0.04))
                                .clipShape(RoundedRectangle(cornerRadius:12))
                            }.buttonStyle(.plain)
                        }
                    }

                    VStack(alignment:.leading, spacing:10) {
                        Text("Recent activity").font(.headline)
                        if model.activity.isEmpty {
                            Text("No new activity returned by the live workspace API.").font(.caption).foregroundStyle(.secondary)
                        } else {
                            ForEach(model.activity.prefix(10), id:\.id) { item in
                                HStack(alignment:.top,spacing:10) {
                                    Circle().fill(.secondary).frame(width:6,height:6).padding(.top,5)
                                    VStack(alignment:.leading,spacing:3) {
                                        Text(item.title).font(.caption)
                                        Text(item.detail).font(.caption2).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                            }
                        }
                    }
                }.padding(16)
            }
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await model.refresh(token:auth.accessToken) }
            .task { await model.start(token:auth.accessToken); await LocalNotice.requestPermission() }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { model.resume(token:auth.accessToken) } else { model.pause() }
            }
            .toolbar {
                ToolbarItem(placement:.topBarTrailing) {
                    Button("Refresh") { Task { await model.refresh(token:auth.accessToken) } }
                }
            }
        }
    }

    private static func timeText(_ date:Date) -> String {
        date.formatted(date:.omitted,time:.shortened)
    }
}

private struct SectionCard<Content:View>: View {
    let title:String; let value:String; let detail:String; @ViewBuilder let content:Content
    var body: some View {
        VStack(alignment:.leading,spacing:8) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title3.bold())
            Text(detail).font(.caption2).foregroundStyle(.secondary)
            content
        }.padding(14).frame(maxWidth:.infinity,alignment:.leading).background(.white.opacity(0.04)).clipShape(RoundedRectangle(cornerRadius:16))
    }
}

private struct MetricCard: View {
    let title:String; let value:String
    var body: some View {
        VStack(alignment:.leading,spacing:4) { Text(value).font(.title2.bold()); Text(title).font(.caption2).foregroundStyle(.secondary) }
            .padding(12).frame(maxWidth:.infinity,alignment:.leading).background(.white.opacity(0.04)).clipShape(RoundedRectangle(cornerRadius:12))
    }
}

private struct MobileService: Identifiable {
    let id:String; let name:String; let icon:String; let url:URL
    static let all:[MobileService] = [
        .init(id:"threat",name:"Threat Intelligence",icon:"eye",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"darkweb",name:"Dark Web Monitoring",icon:"network",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"brand",name:"Brand Protection",icon:"shield",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"physical",name:"Physical Security",icon:"lock.shield",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"compliance",name:"Compliance",icon:"checkmark.seal",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"hunting",name:"Threat Hunting",icon:"scope",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"investigation",name:"Investigation",icon:"magnifyingglass",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"response",name:"Response",icon:"bolt.shield",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"recovery",name:"Recovery",icon:"arrow.clockwise.shield",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!),
        .init(id:"mdi",name:"MDI",icon:"antenna.radiowaves.left.and.right",url:URL(string:"https://customers.cyclothone.online/customer/workspace")!)
    ]
}

struct ActivityItem {
    let id:String
    let title:String
    let detail:String
    let updatedAt:String
}

@MainActor
final class MobileWorkspaceModel: ObservableObject {
    @Published private(set) var organizationName:String?
    @Published private(set) var admissionStatus:String?
    @Published private(set) var requests:[MobileRequest] = []
    @Published private(set) var cases:[MobileCase] = []
    @Published private(set) var activity:[ActivityItem] = []
    @Published private(set) var lastUpdated:Date?
    @Published private(set) var isFresh = false
    @Published var error:String?
    @Published var notice:String?

    private var timer:Task<Void,Never>?
    private var token:String?
    private var snapshotFingerprint:String?

    var activeRequests:Int {
        requests.filter { ["submitted","triage","accepted","in_progress","blocked"].contains($0.status.lowercased()) }.count
    }

    func start(token:String?) async {
        guard self.timer == nil else { return }
        self.token = token
        await refresh(token:token)
        timer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds:5_000_000_000)
                guard !Task.isCancelled else { break }
                if let self, self.isActiveScene { await self.refresh(token:self.token) }
            }
        }
    }

    func resume(token:String?) {
        self.token = token
        if timer == nil {
            Task { await start(token:token) }
        } else {
            Task { await refresh(token:token) }
        }
    }

    func pause() { timer?.cancel(); timer = nil }

    private var isActiveScene:Bool { true }

    func refresh(token:String?) async {
        guard let token, !token.isEmpty else { error = "Authentication session is missing."; return }
        do {
            let state = try await MobileAPI.load(token:token)
            let fingerprint = state.fingerprint
            let changed = snapshotFingerprint != nil && snapshotFingerprint != fingerprint
            snapshotFingerprint = fingerprint
            organizationName = state.organizationName
            admissionStatus = state.admissionStatus
            requests = state.requests
            cases = state.cases
            activity = state.activity
            lastUpdated = Date()
            isFresh = true
            error = nil
            if changed {
                notice = "Workspace updated. New activity is available now."
                await LocalNotice.post(title:"Cyclothone workspace updated",body:"Your customer workspace has new activity.")
            }
        } catch let apiError {
            isFresh = false
            error = apiError.localizedDescription
        }
    }
}

struct MobileRequest: Decodable, Hashable {
    let id:String; let service_key:String; let status:String; let urgency:String; let updated_at:String?
}
struct MobileCase: Decodable, Hashable {
    let id:String
    let organization_id:String
    let service_request_id:String
    let case_id:String
    let created_at:String
    let case_detail:CaseDetail
    enum CodingKeys:String,CodingKey { case id,organization_id,service_request_id,case_id,created_at,case_detail = "case" }
    struct CaseDetail:Decodable,Hashable {
        let id:String
        let case_number:String
        let category:String
        let severity:String
        let status:String
        let title:String
        let summary:String
        let created_at:String
        let updated_at:String
    }
}

private struct MobileState {
    let organizationName:String?
    let admissionStatus:String?
    let requests:[MobileRequest]
    let cases:[MobileCase]
    let activity:[ActivityItem]
    let fingerprint:String
}

private enum MobileAPI {
    static let base = URL(string:"https://cyclothone-api-production.up.railway.app")!

    static func load(token:String) async throws -> MobileState {
        async let orgs: [MobileOrganization] = get("/api/v1/customer/organizations",token:token)
        async let requests: [MobileRequest] = get("/api/v1/customer/service-requests",token:token)
        async let cases: [MobileCase] = get("/api/v1/customer/cases",token:token)
        let (o,r,c) = try await (orgs,requests,cases)
        let org = o.first
        let requestActivity = r.map {
            ActivityItem(id:"request:\($0.id)",title:$0.service_key.replacingOccurrences(of:"_",with:" ").capitalized,detail:"Request · \($0.status) · \($0.urgency)",updatedAt:$0.updated_at ?? "")
        }
        let caseActivity = c.map {
            ActivityItem(id:"case:\($0.id)",title:$0.case_detail.title,detail:"Case \($0.case_detail.case_number) · \($0.case_detail.status) · \($0.case_detail.severity)",updatedAt:$0.case_detail.updated_at)
        }
        let activities = Array((requestActivity + caseActivity).sorted { $0.updatedAt > $1.updatedAt }.prefix(10))
        let fingerprint = (o.map { "\($0.id):\($0.admission_status):\($0.updated_at)" }.joined()
            + r.map { "\($0.id):\($0.status):\($0.updated_at ?? "")" }.joined()
            + c.map { "\($0.id):\($0.case_detail.status):\($0.case_detail.updated_at)" }.joined()).data(using:.utf8).map { SHA256Digest.hex($0) } ?? ""
        return MobileState(organizationName:org?.legal_name,admissionStatus:org?.admission_status,requests:r,cases:c,activity:Array(activities),fingerprint:fingerprint)
    }

    private static func get<T:Decodable>(_ path:String,token:String) async throws -> T {
        var request=URLRequest(url:base.appendingPathComponent(path.trimmingCharacters(in:CharacterSet(charactersIn:"/"))))
        request.setValue("application/json",forHTTPHeaderField:"Accept")
        request.setValue("Bearer \(token)",forHTTPHeaderField:"Authorization")
        request.cachePolicy = URLRequest.CachePolicy.reloadIgnoringLocalCacheData
        let (data,response)=try await URLSession.shared.data(for:request)
        guard let http=response as? HTTPURLResponse else { throw MobileAPIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            if http.statusCode == 401 { throw MobileAPIError.auth }
            throw MobileAPIError.server(http.statusCode)
        }
        return try JSONDecoder().decode(T.self,from:data)
    }
}

private struct MobileOrganization: Decodable {
    let id:String; let legal_name:String; let admission_status:String; let updated_at:String
}

private enum MobileAPIError: LocalizedError {
    case auth, server(Int), invalidResponse
    var errorDescription:String? {
        switch self {
        case .auth: return "Your session expired. Sign in again."
        case .server(let code): return "Workspace service returned HTTP \(code)."
        case .invalidResponse: return "Workspace returned an invalid response."
        }
    }
}

private enum SHA256Digest {
    static func hex(_ data:Data)->String {
        SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined()
    }
}

private enum LocalNotice {
    static func requestPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options:[.alert,.sound,.badge])
    }

    static func post(title:String,body:String) async {
        let center=UNUserNotificationCenter.current()
        let settings=await center.notificationSettings()
        guard settings.authorizationStatus == .authorized else { return }
        let content=UNMutableNotificationContent(); content.title=title; content.body=body
        try? await center.add(UNNotificationRequest(identifier:UUID().uuidString,content:content,trigger:nil))
    }
}

struct WorkspaceView: UIViewRepresentable {
    let url: URL
    func makeUIView(context:Context)->WKWebView { let web=WKWebView(); web.configuration.websiteDataStore = .default(); web.load(URLRequest(url:url)); return web }
    func updateUIView(_ web:WKWebView,context:Context) {}
}
