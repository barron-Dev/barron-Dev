import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var auth = AuthStore()
    @State private var mode: Mode = .entry
    @State private var email = ""; @State private var password = ""; @State private var name = ""; @State private var phone = ""

    enum Mode { case entry, password, magic, register }

    var body: some View {
        Group {
            if auth.authenticated {
                WorkspaceView(url: auth.openWorkspaceURL())
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

struct WorkspaceView: UIViewRepresentable {
    let url: URL
    func makeUIView(context:Context)->WKWebView { let web=WKWebView(); web.configuration.websiteDataStore = .default(); web.load(URLRequest(url:url)); return web }
    func updateUIView(_ web:WKWebView,context:Context) {}
}