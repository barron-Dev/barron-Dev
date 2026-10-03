package online.cyclothone.mobile

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.EditText
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import kotlin.concurrent.thread
import android.util.Base64

class MainActivity : Activity() {
    companion object {
        private const val SUPABASE_URL = "https://whcomikcftbousoqzeal.supabase.co"
        private const val REDIRECT_URI = "cyclothone://auth/callback"
        private const val WORKSPACE_URL = "https://customers.cyclothone.online/mobile-auth"
        private const val API_BASE = "https://cyclothone-api-production.up.railway.app"
        private const val PREFS = "cyclothone_auth"
        private const val ACCESS_TOKEN = "access_token"
        private const val REFRESH_TOKEN = "refresh_token"
        private const val CODE_VERIFIER = "code_verifier"
        private const val STATE = "oauth_state"
        private const val SUPABASE_KEY = "sb_publishable_3qKBAIdxxrDuE8gEGwJICg_5NEH3CVU"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "cyclothone-session-v1"
        private const val ENCRYPTED_ACCESS_TOKEN = "encrypted_access_token"
        private const val ENCRYPTED_REFRESH_TOKEN = "encrypted_refresh_token"
        private fun b64(b:ByteArray)=android.util.Base64.encodeToString(b,android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        private fun verifier()=ByteArray(32).also{SecureRandom().nextBytes(it)}.let(::b64)
        private fun challenge(v:String)=b64(MessageDigest.getInstance("SHA-256").digest(v.toByteArray(Charsets.US_ASCII)))
        private fun enc(v:String)=URLEncoder.encode(v,Charsets.UTF_8.name())
    }
    private val prefs by lazy{getSharedPreferences(PREFS,MODE_PRIVATE)}
    private val sessionCrypto by lazy { SessionCrypto() }
    private lateinit var status:TextView
    private lateinit var signIn:Button
    private var emailInput: EditText? = null
    private var passwordInput: EditText? = null
    private var magicEmailInput: EditText? = null

    override fun onCreate(state:Bundle?){
        super.onCreate(state); showEntry()
        if(state==null) when { intent?.data!=null->handleCallback(intent.data!!); hasSession()->openWorkspace() }
    }
    override fun onNewIntent(intent:Intent?){super.onNewIntent(intent);setIntent(intent);intent?.data?.let(::handleCallback)}

    private fun showEntry(){
        val root=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;gravity=Gravity.CENTER;setPadding(48,48,48,48);setBackgroundColor(Color.rgb(4,16,27))}
        val title=TextView(this).apply{text="CYCLOTHONE";textSize=26f;setTextColor(Color.WHITE);gravity=Gravity.CENTER}
        val sub=TextView(this).apply{text="Secure mobile access";textSize=14f;setTextColor(Color.LTGRAY);gravity=Gravity.CENTER;setPadding(0,12,0,24)}
        status=TextView(this).apply{text="Sign in to continue.";textSize=13f;setTextColor(Color.LTGRAY);gravity=Gravity.CENTER;setPadding(0,0,0,20)}
        signIn=Button(this).apply{text="Sign in with Google";setOnClickListener{startGoogle()}}
        val github=Button(this).apply{text="Continue with GitHub";setOnClickListener{startGithub()}}
        val email=Button(this).apply{text="Email / Magic link";setOnClickListener{showMagicLink()}}
        val register=Button(this).apply{text="Create account / Registration";setOnClickListener{showRegistration()}}
        val password=Button(this).apply{text="Email + Password";setOnClickListener{showPasswordLogin()}}
        root.addView(title,LinearLayout.LayoutParams(-1,-2));root.addView(sub,LinearLayout.LayoutParams(-1,-2));root.addView(status,LinearLayout.LayoutParams(-1,-2))
        root.addView(signIn,LinearLayout.LayoutParams(-1,-2));root.addView(github,LinearLayout.LayoutParams(-1,-2))
        root.addView(email,LinearLayout.LayoutParams(-1,-2));root.addView(register,LinearLayout.LayoutParams(-1,-2));root.addView(password,LinearLayout.LayoutParams(-1,-2));setContentView(root)
    }

    private fun showMagicLink() {
        val root = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; gravity=Gravity.CENTER; setPadding(48,48,48,48); setBackgroundColor(Color.rgb(4,16,27)) }
        val title=TextView(this).apply{text="Email sign-in";textSize=24f;setTextColor(Color.WHITE);gravity=Gravity.CENTER}
        status=TextView(this).apply{text="We will send a secure sign-in link.";textSize=13f;setTextColor(Color.LTGRAY);gravity=Gravity.CENTER;setPadding(0,12,0,20)}
        magicEmailInput=EditText(this).apply{hint="Email";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS}
        val submit=Button(this).apply{text="Send secure link";setOnClickListener{sendMagicLink()}}
        val back=Button(this).apply{text="Back";setOnClickListener{showEntry()}}
        root.addView(title);root.addView(status);root.addView(magicEmailInput);root.addView(submit);root.addView(back);setContentView(root)
    }

    private fun sendMagicLink() {
        val email=magicEmailInput?.text?.toString()?.trim()?.lowercase().orEmpty()
        if(email.isBlank()){status.text="Enter your email address.";return}
        status.text="Sending secure link…"
        thread { try {
            val body=JSONObject().apply{put("email",email);put("create_user",false)}.toString()
            val c=(URL("$SUPABASE_URL/auth/v1/otp?redirect_to="+enc(REDIRECT_URI)).openConnection() as HttpURLConnection).apply{requestMethod="POST";doOutput=true;connectTimeout=15000;readTimeout=15000;setRequestProperty("apikey",SUPABASE_KEY);setRequestProperty("Content-Type","application/json");setRequestProperty("Accept","application/json")}
            c.outputStream.use{it.write(body.toByteArray(Charsets.UTF_8))}
            val input=if(c.responseCode in 200..299)c.inputStream else c.errorStream;val text=input.bufferedReader().use{it.readText()}
            if(c.responseCode !in 200..299) throw IllegalStateException(runCatching{JSONObject(text).optString("msg")}.getOrNull().orEmpty().ifBlank{"Unable to send sign-in link (${c.responseCode})."})
            runOnUiThread{status.text="Secure link sent. Open it from this device to finish sign-in."}
        } catch(e:Exception){runOnUiThread{status.text=e.message?:"Unable to send sign-in link."}}
        }
    }
    private fun showPasswordLogin() {
        val root = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; gravity=Gravity.CENTER; setPadding(48,48,48,48); setBackgroundColor(Color.rgb(4,16,27)) }
        val title=TextView(this).apply{text="Email + Password";textSize=24f;setTextColor(Color.WHITE);gravity=Gravity.CENTER}
        status=TextView(this).apply{text="Sign in securely.";textSize=13f;setTextColor(Color.LTGRAY);gravity=Gravity.CENTER;setPadding(0,12,0,20)}
        emailInput=EditText(this).apply{hint="Email";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS}
        passwordInput=EditText(this).apply{hint="Password";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD}
        val submit=Button(this).apply{text="Sign in";setOnClickListener{nativePasswordSignIn()}}
        val back=Button(this).apply{text="Back";setOnClickListener{showEntry()}}
        root.addView(title);root.addView(status);root.addView(emailInput);root.addView(passwordInput);root.addView(submit);root.addView(back);setContentView(root)
    }

    private fun showRegistration() {
        val root = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; gravity=Gravity.CENTER; setPadding(48,48,48,48); setBackgroundColor(Color.rgb(4,16,27)) }
        val title=TextView(this).apply{text="Create Cyclothone account";textSize=24f;setTextColor(Color.WHITE);gravity=Gravity.CENTER}
        status=TextView(this).apply{text="Use your real details. Email verification may be required.";textSize=13f;setTextColor(Color.LTGRAY);gravity=Gravity.CENTER;setPadding(0,12,0,20)}
        val name=EditText(this).apply{hint="Name or company name";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY)}
        emailInput=EditText(this).apply{hint="Email";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS}
        val phone=EditText(this).apply{hint="Phone";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_PHONE}
        passwordInput=EditText(this).apply{hint="Password";setTextColor(Color.WHITE);setHintTextColor(Color.GRAY);inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD}
        val submit=Button(this).apply{text="Create account";setOnClickListener{nativeRegister(name.text.toString(),phone.text.toString())}}
        val back=Button(this).apply{text="Back";setOnClickListener{showEntry()}}
        root.addView(title);root.addView(status);root.addView(name);root.addView(emailInput);root.addView(phone);root.addView(passwordInput);root.addView(submit);root.addView(back);setContentView(root)
    }

    private fun nativePasswordSignIn() {
        val email=emailInput?.text?.toString()?.trim()?.lowercase().orEmpty(); val password=passwordInput?.text?.toString().orEmpty()
        if(email.isBlank()||password.isBlank()){status.text="Email and password are required.";return}
        status.text="Signing in…"
        thread { try { val s=passwordToken(email,password); saveSession(s.first,s.second); runOnUiThread{openWorkspace()} } catch(e:Exception){runOnUiThread{status.text=e.message?:"Sign-in failed."}} }
    }

    private fun nativeRegister(name:String,phone:String) {
        val email=emailInput?.text?.toString()?.trim()?.lowercase().orEmpty(); val password=passwordInput?.text?.toString().orEmpty()
        if(name.trim().isBlank()||email.isBlank()||phone.trim().isBlank()||password.isBlank()){status.text="Name, email, phone and password are required.";return}
        status.text="Creating account…"
        thread { try { val response=signup(email,password,name.trim(),phone.trim()); if(response.first!=null){saveSession(response.first!!,response.second!!);runOnUiThread{openWorkspace()}} else runOnUiThread{status.text="Account created. Check your email to verify, then sign in."} } catch(e:Exception){runOnUiThread{status.text=e.message?:"Registration failed."}} }
    }

    private fun passwordToken(email:String,password:String):Pair<String,String>{
        return tokenRequest("grant_type=password","email="+enc(email)+"&password="+enc(password))
    }

    private fun signup(email:String,password:String,name:String,phone:String):Pair<String?,String?>{
        val body=JSONObject().apply{put("email",email);put("password",password);put("data",JSONObject().apply{put("account_name",name);put("phone_number",phone);put("onboarding_stage","registered")})}.toString()
        val c=(URL("$SUPABASE_URL/auth/v1/signup?redirect_to="+enc(REDIRECT_URI)).openConnection() as HttpURLConnection).apply{requestMethod="POST";doOutput=true;connectTimeout=15000;readTimeout=15000;setRequestProperty("apikey",SUPABASE_KEY);setRequestProperty("Content-Type","application/json");setRequestProperty("Accept","application/json")}
        c.outputStream.use{it.write(body.toByteArray(Charsets.UTF_8))}
        val input=if(c.responseCode in 200..299)c.inputStream else c.errorStream;val text=input.bufferedReader().use{it.readText()}
        if(c.responseCode !in 200..299) throw IllegalStateException(runCatching{JSONObject(text).optString("msg")}.getOrNull().orEmpty().ifBlank{"Registration failed (${c.responseCode})."})
        val j=JSONObject(text); val a=j.optString("access_token").takeIf{it.isNotBlank()}; val r=j.optString("refresh_token").takeIf{it.isNotBlank()}; return a to r
    }

    private fun tokenRequest(query:String,body:String):Pair<String,String>{
        val c=(URL("$SUPABASE_URL/auth/v1/token?"+query).openConnection() as HttpURLConnection).apply{requestMethod="POST";doOutput=true;connectTimeout=15000;readTimeout=15000;setRequestProperty("apikey",SUPABASE_KEY);setRequestProperty("Content-Type","application/x-www-form-urlencoded");setRequestProperty("Accept","application/json")}
        c.outputStream.use{it.write(body.toByteArray(Charsets.UTF_8))}
        val input=if(c.responseCode in 200..299)c.inputStream else c.errorStream;val text=input.bufferedReader().use{it.readText()}
        if(c.responseCode !in 200..299) throw IllegalStateException(runCatching{JSONObject(text).optString("msg")}.getOrNull().orEmpty().ifBlank{"Authentication failed (${c.responseCode})."})
        val j=JSONObject(text);val a=j.optString("access_token");val r=j.optString("refresh_token");if(a.isBlank()||r.isBlank())throw IllegalStateException("Authentication returned no active session.");return a to r
    }

    private fun startOAuth(provider:String){
        val v=verifier();val state=UUID.randomUUID().toString();prefs.edit().putString(CODE_VERIFIER,v).putString(STATE,state).apply()
        val url=buildString{
            append("$SUPABASE_URL/auth/v1/authorize?provider=").append(enc(provider))
            append("&redirect_to=").append(enc(REDIRECT_URI));append("&code_challenge=").append(enc(challenge(v)))
            append("&code_challenge_method=S256");append("&state=").append(enc(state));append("&prompt=select_account")
        }
        status.text="Opening ${provider.replaceFirstChar { it.uppercase() }} securely…";signIn.isEnabled=false
        runCatching{startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))}.onFailure{status.text="Unable to open the secure sign-in browser.";signIn.isEnabled=true}
    }

    private fun startGoogle()=startOAuth("google")
    private fun startGithub()=startOAuth("github")
    private fun openWeb(path:String){ startActivity(Intent(Intent.ACTION_VIEW,Uri.parse("https://customers.cyclothone.online$path"))) }

    private fun handleCallback(uri:Uri){
        if(uri.scheme!="cyclothone"||uri.host!="auth"||uri.path!="/callback")return
        uri.getQueryParameter("error")?.let{status.text=uri.getQueryParameter("error_description")?:"Authentication was cancelled.";signIn.isEnabled=true;clearPkce();return}
        val fragment=uri.fragment.orEmpty()
        val fragmentParams=fragment.split("&").mapNotNull{part->part.split("=",limit=2).takeIf{it.size==2}?.let{it[0] to java.net.URLDecoder.decode(it[1],"UTF-8")}}.toMap()
        val access=fragmentParams["access_token"];val refresh=fragmentParams["refresh_token"]
        if(!access.isNullOrBlank()&&!refresh.isNullOrBlank()){saveSession(access,refresh);clearPkce();runOnUiThread{openWorkspace()};return}
        val code=uri.getQueryParameter("code");val returned=uri.getQueryParameter("state");val expected=prefs.getString(STATE,null);val v=prefs.getString(CODE_VERIFIER,null)
        if(code.isNullOrBlank()||v.isNullOrBlank()||expected.isNullOrBlank()||returned!=expected){status.text="Secure sign-in could not be verified. Please try again.";signIn.isEnabled=true;clearPkce();return}
        status.text="Completing secure sign-in…";signIn.isEnabled=false
        thread{try{val s=exchange(code,v);saveSession(s.first,s.second);clearPkce();runOnUiThread{openWorkspace()}}
        catch(e:Exception){clearPkce();runOnUiThread{status.text=e.message?:"Unable to complete sign-in.";signIn.isEnabled=true}}}
    }
    private fun exchange(code:String,v:String):Pair<String,String>{
        val c=(URL("$SUPABASE_URL/auth/v1/token?grant_type=pkce").openConnection() as HttpURLConnection).apply{
            requestMethod="POST";doOutput=true;connectTimeout=15000;readTimeout=15000;setRequestProperty("apikey",SUPABASE_KEY);setRequestProperty("Content-Type","application/x-www-form-urlencoded");setRequestProperty("Accept","application/json")}
        c.outputStream.use{it.write("auth_code=${enc(code)}&code_verifier=${enc(v)}".toByteArray(Charsets.UTF_8))}
        val input=if(c.responseCode in 200..299)c.inputStream else c.errorStream;val body=input.bufferedReader().use{it.readText()}
        if(c.responseCode !in 200..299){val msg=runCatching{JSONObject(body).optString("msg")}.getOrNull().orEmpty();throw IllegalStateException(if(msg.isNotBlank())msg else "Authentication exchange failed (${c.responseCode}).")}
        val j=JSONObject(body);val a=j.optString("access_token");val r=j.optString("refresh_token");if(a.isBlank()||r.isBlank())throw IllegalStateException("Authentication exchange returned no session.");return a to r
    }

    private fun migrateLegacySession() {
        val legacyAccess = prefs.getString(ACCESS_TOKEN, null)
        val legacyRefresh = prefs.getString(REFRESH_TOKEN, null)
        if (!legacyAccess.isNullOrBlank() && !legacyRefresh.isNullOrBlank()) {
            saveSession(legacyAccess, legacyRefresh)
            prefs.edit().remove(ACCESS_TOKEN).remove(REFRESH_TOKEN).apply()
        }
    }

    private fun saveSession(access: String, refresh: String) {
        prefs.edit()
            .putString(ENCRYPTED_ACCESS_TOKEN, sessionCrypto.encrypt(access))
            .putString(ENCRYPTED_REFRESH_TOKEN, sessionCrypto.encrypt(refresh))
            .apply()
    }

    private fun readSession(): Pair<String, String>? {
        migrateLegacySession()
        val a = prefs.getString(ENCRYPTED_ACCESS_TOKEN, null)?.let { runCatching { sessionCrypto.decrypt(it) }.getOrNull() }
        val r = prefs.getString(ENCRYPTED_REFRESH_TOKEN, null)?.let { runCatching { sessionCrypto.decrypt(it) }.getOrNull() }
        return if (!a.isNullOrBlank() && !r.isNullOrBlank()) a to r else null
    }

    private val workspaceHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val workspaceRefresh = object : Runnable {
        override fun run() {
            refreshNativeWorkspace()
            workspaceHandler.postDelayed(this, 15000L)
        }
    }

    private fun openWorkspace() {
        val session = readSession() ?: run { showEntry(); return }
        showNativeWorkspace(session.first)
        workspaceHandler.removeCallbacks(workspaceRefresh)
        workspaceHandler.post(workspaceRefresh)
    }

    private var workspaceSummary: TextView? = null
    private var workspaceToken: String? = null

    private fun showNativeWorkspace(token: String) {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 32)
            setBackgroundColor(Color.rgb(4, 16, 27))
        }
        val title = TextView(this).apply {
            text = "CYCLOTHONE"
            textSize = 24f
            setTextColor(Color.WHITE)
        }
        val subtitle = TextView(this).apply {
            text = "Mobile workspace"
            textSize = 13f
            setTextColor(Color.LTGRAY)
            setPadding(0, 6, 0, 18)
        }
        status = TextView(this).apply {
            text = "Loading live workspace…"
            textSize = 14f
            setTextColor(Color.LTGRAY)
            setPadding(0, 0, 0, 18)
        }
        workspaceSummary = TextView(this).apply {
            text = "Loading live account state…"
            textSize = 16f
            setTextColor(Color.WHITE)
            setPadding(0, 0, 0, 18)
        }
        val refresh = Button(this).apply {
            text = "Refresh"
            setOnClickListener { refreshNativeWorkspace() }
        }
        val fullWorkspace = Button(this).apply {
            text = "Open full workspace"
            setOnClickListener { openWebWorkspace() }
        }
        val signOut = Button(this).apply {
            text = "Sign out"
            setOnClickListener {
                workspaceHandler.removeCallbacks(workspaceRefresh)
                clearSession()
                showEntry()
            }
        }
        root.addView(title)
        root.addView(subtitle)
        root.addView(status)
        root.addView(workspaceSummary)
        root.addView(refresh)
        root.addView(fullWorkspace)
        root.addView(signOut)
        setContentView(root)
        workspaceToken = token
        refreshNativeWorkspace()
    }

    private fun refreshNativeWorkspace() {
        val token = workspaceToken ?: readSession()?.first ?: return
        status.text = "Syncing live workspace…"
        thread {
            try {
                val organizations = apiGet("$API_BASE/api/v1/customer/organizations", token).optJSONArray("organizations")
                val requests = apiGet("$API_BASE/api/v1/customer/service-requests", token).optJSONArray("service_requests")
                val cases = apiGet("$API_BASE/api/v1/customer/cases", token).optJSONArray("cases")
                val orgCount = organizations?.length() ?: 0
                val requestCount = requests?.length() ?: 0
                val caseCount = cases?.length() ?: 0
                val org = organizations?.optJSONObject(0)
                val name = org?.optString("legal_name").orEmpty().ifBlank { "No organization" }
                val admission = org?.optString("admission_status").orEmpty().ifBlank {
                    org?.optString("verification_status").orEmpty().ifBlank { "Account authenticated" }
                }
                runOnUiThread {
                    workspaceSummary?.text =
                        "$name\nWorkspace: $admission\n\nOrganizations: $orgCount\nService requests: $requestCount\nCases: $caseCount"
                    status.text = "Live data synced."
                }
            } catch (e: Exception) {
                runOnUiThread {
                    status.text = e.message ?: "Live workspace sync failed."
                }
            }
        }
    }

    private fun apiGet(endpoint: String, token: String): JSONObject {
        val c = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15000
            readTimeout = 15000
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("Accept", "application/json")
        }
        val input = if (c.responseCode in 200..299) c.inputStream else c.errorStream
        val body = input.bufferedReader().use { it.readText() }
        if (c.responseCode !in 200..299) {
            val detail = runCatching { JSONObject(body).optString("detail") }.getOrNull().orEmpty()
            throw IllegalStateException(detail.ifBlank { "Live workspace request failed (${c.responseCode})." })
        }
        return JSONObject(body)
    }

    private fun openWebWorkspace() {
        val session = readSession() ?: run { showEntry(); return }
        val handoff = "$WORKSPACE_URL#access_token=${enc(session.first)}&refresh_token=${enc(session.second)}&token_type=bearer&type=recovery"
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(handoff)))
    }

    private fun clearSession() {
        prefs.edit()
            .remove(ENCRYPTED_ACCESS_TOKEN)
            .remove(ENCRYPTED_REFRESH_TOKEN)
            .remove(ACCESS_TOKEN)
            .remove(REFRESH_TOKEN)
            .apply()
        workspaceToken = null
    }

    private fun hasSession()=readSession()!=null
    private fun clearPkce(){prefs.edit().remove(CODE_VERIFIER).remove(STATE).apply()}

    private class SessionCrypto {
        private val key: SecretKey
        init {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val existing = ks.getKey(KEY_ALIAS, null) as? SecretKey
            key = existing ?: KeyGenerator.getInstance("AES", KEYSTORE).apply {
                init(android.security.keystore.KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
                ).setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                 .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                 .setRandomizedEncryptionRequired(true)
                 .build())
            }.generateKey()
        }
        fun encrypt(value: String): String {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            return Base64.encodeToString(iv + ciphertext, Base64.NO_WRAP)
        }
        fun decrypt(encoded: String): String {
            val packed = Base64.decode(encoded, Base64.NO_WRAP)
            require(packed.size > 12)
            val iv = packed.copyOfRange(0, 12)
            val ciphertext = packed.copyOfRange(12, packed.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            return cipher.doFinal(ciphertext).toString(Charsets.UTF_8)
        }
    }
}