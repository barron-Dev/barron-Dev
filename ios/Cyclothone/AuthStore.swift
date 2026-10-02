import Foundation
import AuthenticationServices
import Security
import CryptoKit
import UIKit

@MainActor
final class AuthStore: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    static let supabaseURL = URL(string: "https://whcomikcftbousoqzeal.supabase.co")!
    static let redirectURI = "cyclothone-ios://auth/callback"
    static let workspaceURL = URL(string: "https://customers.cyclothone.online/mobile-auth")!
    static let publicKey = "sb_publishable_3qKBAIdxxrDuE8gEGwJICg_5NEH3CVU"

    @Published var message = "Sign in to continue."
    @Published var authenticated = false
    var accessToken: String? { keychain.accessToken }
    var refreshToken: String? { keychain.refreshToken }
    private var session: ASWebAuthenticationSession?
    private let keychain = KeychainStore()
    private var pkceVerifier: String?
    private var oauthState: String?

    override init() {
        super.init()
        authenticated = keychain.accessToken != nil
    }

    func signIn(provider: String) {
        let verifier = Self.randomURLSafe(48)
        let state = Self.randomURLSafe(32)
        pkceVerifier = verifier
        oauthState = state
        var components = URLComponents(url: Self.supabaseURL.appendingPathComponent("auth/v1/authorize"), resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "provider", value: provider),
            URLQueryItem(name: "redirect_to", value: Self.redirectURI),
            URLQueryItem(name: "flow_type", value: "pkce"),
            URLQueryItem(name: "code_challenge", value: Self.codeChallenge(verifier)),
            URLQueryItem(name: "code_challenge_method", value: "s256"),
            URLQueryItem(name: "state", value: state)
        ]
        guard let url = components.url else { message = "Unable to start secure sign-in."; return }
        message = "Opening secure sign-in…"
        session = ASWebAuthenticationSession(url: url, callbackURLScheme: "cyclothone-ios") { [weak self] callback, error in
            Task { @MainActor in
                guard let self else { return }
                defer { self.pkceVerifier = nil; self.oauthState = nil }
                if let error { self.message = error.localizedDescription; return }
                guard let callback,
                      let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
                      let code = components.queryItems?.first(where: { $0.name == "code" })?.value,
                      let returnedState = components.queryItems?.first(where: { $0.name == "state" })?.value,
                      returnedState == self.oauthState,
                      let verifier = self.pkceVerifier else {
                    self.message = "Secure sign-in callback was not valid."; return
                }
                do {
                    let tokens = try await self.exchangePKCE(code: code, verifier: verifier)
                    self.keychain.accessToken = tokens.access
                    self.keychain.refreshToken = tokens.refresh
                    self.authenticated = true
                    self.message = "Signed in securely."
                } catch { self.message = error.localizedDescription }
            }
        }
        session?.presentationContextProvider = self
        session?.prefersEphemeralWebBrowserSession = false
        session?.start()
    }

    func passwordSignIn(email: String, password: String) async {
        do {
            let tokens = try await tokenRequest(body: "grant_type=password&email=\(enc(email))&password=\(enc(password))")
            keychain.accessToken = tokens.access; keychain.refreshToken = tokens.refresh; authenticated = true
            message = "Signed in securely."
        } catch { message = error.localizedDescription }
    }

    func register(name: String, email: String, phone: String, password: String) async {
        do {
            var request = URLRequest(url: Self.supabaseURL.appendingPathComponent("auth/v1/signup"))
            request.httpMethod = "POST"; request.setValue(Self.publicKey, forHTTPHeaderField: "apikey")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["email":email,"password":password,"data":["account_name":name,"phone_number":phone,"onboarding_stage":"registered"]])
            let (data,response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw AuthError.api(message: apiMessage(data) ?? "Registration failed.") }
            if let obj = try JSONSerialization.jsonObject(with: data) as? [String:Any],
               let access = obj["access_token"] as? String, let refresh = obj["refresh_token"] as? String {
                keychain.accessToken = access; keychain.refreshToken = refresh; authenticated = true
            } else { message = "Account created. Check your email to verify, then sign in." }
        } catch { message = error.localizedDescription }
    }

    func sendMagicLink(email: String) async {
        do {
            var request = URLRequest(url: Self.supabaseURL.appendingPathComponent("auth/v1/otp"))
            request.httpMethod = "POST"; request.setValue(Self.publicKey, forHTTPHeaderField: "apikey")
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["email":email,"create_user":false,"options":["email_redirect_to":Self.redirectURI]])
            let (data,response)=try await URLSession.shared.data(for: request)
            guard let http=response as? HTTPURLResponse,(200..<300).contains(http.statusCode) else { throw AuthError.api(message: apiMessage(data) ?? "Unable to send sign-in link.") }
            message = "Secure link sent. Open it on this device to finish sign-in."
        } catch { message = error.localizedDescription }
    }

    private func exchangePKCE(code: String, verifier: String) async throws -> Tokens {
        try await tokenRequest(body: "grant_type=pkce&auth_code=\(enc(code))&code_verifier=\(enc(verifier))")
    }

    private func tokenRequest(body: String) async throws -> Tokens {
        var request=URLRequest(url: Self.supabaseURL.appendingPathComponent("auth/v1/token"))
        request.httpMethod="POST"; request.setValue(Self.publicKey,forHTTPHeaderField:"apikey"); request.setValue("application/x-www-form-urlencoded",forHTTPHeaderField:"Content-Type"); request.httpBody=body.data(using:.utf8)
        let (data,response)=try await URLSession.shared.data(for:request)
        guard let http=response as? HTTPURLResponse,(200..<300).contains(http.statusCode) else { throw AuthError.api(message: apiMessage(data) ?? "Authentication failed.") }
        let obj=try JSONDecoder().decode(TokenResponse.self,from:data)
        return Tokens(access:obj.access_token,refresh:obj.refresh_token)
    }

    func signOut() {
        session?.cancel()
        session = nil
        pkceVerifier = nil
        oauthState = nil
        keychain.accessToken = nil
        keychain.refreshToken = nil
        authenticated = false
        message = "Signed out securely."
    }

    func openWorkspaceURL() -> URL {
        var components=URLComponents(url:Self.workspaceURL,resolvingAgainstBaseURL:false)!
        components.fragment="access_token=\(enc(keychain.accessToken ?? ""))&refresh_token=\(enc(keychain.refreshToken ?? ""))"
        return components.url!
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first?.keyWindow ?? ASPresentationAnchor()
    }

    private func enc(_ value:String)->String { value.addingPercentEncoding(withAllowedCharacters:.urlQueryAllowed) ?? value }
    private static func randomURLSafe(_ bytes:Int)->String {
        var data=Data(count:bytes); _=data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault,bytes,$0.baseAddress!) }
        return data.base64EncodedString().replacingOccurrences(of:"+",with:"-").replacingOccurrences(of:"/",with:"_").replacingOccurrences(of:"=",with:"")
    }
    private static func codeChallenge(_ verifier:String)->String {
        let digest=SHA256.hash(data:Data(verifier.utf8))
        return Data(digest).base64EncodedString().replacingOccurrences(of:"+",with:"-").replacingOccurrences(of:"/",with:"_").replacingOccurrences(of:"=",with:"")
    }
    private func apiMessage(_ data:Data)->String? {
        guard let obj=try? JSONSerialization.jsonObject(with:data) as? [String:Any] else { return nil }
        return (obj["msg"] as? String) ?? (obj["message"] as? String) ?? (obj["error_description"] as? String)
    }
}

struct TokenResponse: Decodable { let access_token:String; let refresh_token:String }
struct Tokens { let access:String; let refresh:String }
enum AuthError: LocalizedError { case api(message:String); var errorDescription:String? { if case .api(let message)=self { return message }; return nil } }

final class KeychainStore {
    private let service="online.cyclothone.mobile"
    var accessToken:String? { get { read("access") } set { write("access",newValue) } }
    var refreshToken:String? { get { read("refresh") } set { write("refresh",newValue) } }
    private func write(_ key:String,_ value:String?) {
        let q:[String:Any]=[kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:service,kSecAttrAccount as String:key]
        SecItemDelete(q as CFDictionary)
        guard let value else { return }
        var item=q; item[kSecValueData as String]=Data(value.utf8); item[kSecAttrAccessible as String]=kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(item as CFDictionary,nil)
    }
    private func read(_ key:String)->String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result:CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary,&result)==errSecSuccess,let data=result as? Data else { return nil }
        return String(data:data,encoding:.utf8)
    }
}