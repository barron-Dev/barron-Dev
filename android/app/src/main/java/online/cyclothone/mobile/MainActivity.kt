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
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import kotlin.concurrent.thread

class MainActivity : Activity() {
    companion object {
        private const val SUPABASE_URL = "https://whcomikcftbousoqzeal.supabase.co"
        private const val REDIRECT_URI = "cyclothone://auth/callback"
        private const val WORKSPACE_URL = "https://customers.cyclothone.online/mobile-auth"
        private const val PREFS = "cyclothone_auth"
        private const val ACCESS_TOKEN = "access_token"
        private const val REFRESH_TOKEN = "refresh_token"
        private const val CODE_VERIFIER = "code_verifier"
        private const val STATE = "oauth_state"
        private const val SUPABASE_KEY = "sb_publishable_3qKBAIdxxrDuE8gEGwJICg_5NEH3CVU"
        private fun b64(b:ByteArray)=android.util.Base64.encodeToString(b,android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        private fun verifier()=ByteArray(32).also{SecureRandom().nextBytes(it)}.let(::b64)
        private fun challenge(v:String)=b64(MessageDigest.getInstance("SHA-256").digest(v.toByteArray(Charsets.US_ASCII)))
        private fun enc(v:String)=URLEncoder.encode(v,Charsets.UTF_8.name())
    }
    private val prefs by lazy{getSharedPreferences(PREFS,MODE_PRIVATE)}
    private lateinit var status:TextView
    private lateinit var signIn:Button

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
        val email=Button(this).apply{text="Email / Magic link";setOnClickListener{openWeb("/login")}}
        val register=Button(this).apply{text="Create account / Registration";setOnClickListener{openWeb("/register")}}
        val password=Button(this).apply{text="Email + Password";setOnClickListener{openWeb("/login")}}
        root.addView(title,LinearLayout.LayoutParams(-1,-2));root.addView(sub,LinearLayout.LayoutParams(-1,-2));root.addView(status,LinearLayout.LayoutParams(-1,-2))
        root.addView(signIn,LinearLayout.LayoutParams(-1,-2));root.addView(github,LinearLayout.LayoutParams(-1,-2))
        root.addView(email,LinearLayout.LayoutParams(-1,-2));root.addView(register,LinearLayout.LayoutParams(-1,-2));root.addView(password,LinearLayout.LayoutParams(-1,-2));setContentView(root)
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
        uri.getQueryParameter("error")?.let{status.text=uri.getQueryParameter("error_description")?:"Google sign-in was cancelled.";signIn.isEnabled=true;clearPkce();return}
        val code=uri.getQueryParameter("code");val returned=uri.getQueryParameter("state");val expected=prefs.getString(STATE,null);val v=prefs.getString(CODE_VERIFIER,null)
        if(code.isNullOrBlank()||v.isNullOrBlank()||expected.isNullOrBlank()||returned!=expected){status.text="Secure sign-in could not be verified. Please try again.";signIn.isEnabled=true;clearPkce();return}
        status.text="Completing secure sign-in…";signIn.isEnabled=false
        thread{try{val s=exchange(code,v);prefs.edit().putString(ACCESS_TOKEN,s.first).putString(REFRESH_TOKEN,s.second).apply();clearPkce();runOnUiThread{openWorkspace()}}
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

    private fun openWorkspace(){
        val a=prefs.getString(ACCESS_TOKEN,null);val r=prefs.getString(REFRESH_TOKEN,null);if(a.isNullOrBlank()||r.isNullOrBlank()){showEntry();return}
        val web=WebView(this).apply{settings.javaScriptEnabled=true;settings.domStorageEnabled=true;settings.allowFileAccess=false;settings.allowContentAccess=false;webViewClient=WebViewClient()}
        val handoff="$WORKSPACE_URL#access_token=${enc(a)}&refresh_token=${enc(r)}&token_type=bearer&type=recovery";web.loadUrl(handoff);setContentView(web)
    }
    private fun hasSession()=!prefs.getString(ACCESS_TOKEN,null).isNullOrBlank()&&!prefs.getString(REFRESH_TOKEN,null).isNullOrBlank()
    private fun clearPkce(){prefs.edit().remove(CODE_VERIFIER).remove(STATE).apply()}
}