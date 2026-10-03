package online.cyclothone.mobile

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import kotlin.concurrent.thread

class DeveloperActivity : Activity() {
    companion object {
        const val SUPABASE_URL = "https://whcomikcftbousoqzeal.supabase.co"
        const val API_BASE = "https://cyclothone-api-production.up.railway.app"
        const val REDIRECT = "cyclothone://developer/callback"
        const val PREFS = "cyclothone_developer"
        const val TOKEN = "access_token"
        const val ENCRYPTED_TOKEN = "encrypted_access_token"
        const val STATE = "oauth_state"
        const val VERIFIER = "pkce_verifier"
        const val SUPABASE_KEY = "sb_publishable_3qKBAIdxxrDuE8gEGwJICg_5NEH3CVU"
        fun enc(v:String)=URLEncoder.encode(v,"UTF-8")
        fun b64(v:ByteArray)=android.util.Base64.encodeToString(v,android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
    }
    val prefs by lazy { getSharedPreferences(PREFS, MODE_PRIVATE) }
    val sessionCrypto by lazy { MainActivity.SessionCrypto() }
    lateinit var status:TextView
    lateinit var list:LinearLayout

    override fun onCreate(state:Bundle?) {
        super.onCreate(state)
        if (intent?.data != null) { showEntry(); handleCallback(intent.data!!); return }
        if (!prefs.getString(TOKEN,null).isNullOrBlank()) showPortal() else showEntry()
    }
    override fun onNewIntent(i:Intent?) { super.onNewIntent(i); setIntent(i); i?.data?.let{handleCallback(it)} }

    fun showEntry() {
        val r=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(40,60,40,40)}
        r.addView(TextView(this).apply{text="CYCLOTHONE Developer";textSize=26f})
        status=TextView(this).apply{text="Developer access";setPadding(0,16,0,24)};r.addView(status)
        r.addView(Button(this).apply{text="Sign in with Google";setOnClickListener{startOAuth("google")}})
        r.addView(Button(this).apply{text="Continue with GitHub";setOnClickListener{startOAuth("github")}})
        setContentView(r)
    }
    fun startOAuth(provider:String) {
        val v=b64(ByteArray(32).also{SecureRandom().nextBytes(it)})
        val s=UUID.randomUUID().toString()
        prefs.edit().putString(VERIFIER,v).putString(STATE,s).apply()
        val c=b64(MessageDigest.getInstance("SHA-256").digest(v.toByteArray(Charsets.US_ASCII)))
        val u=SUPABASE_URL+"/auth/v1/authorize?provider="+enc(provider)+"&redirect_to="+enc(REDIRECT)+"&code_challenge="+enc(c)+"&code_challenge_method=S256&state="+enc(s)+"&prompt=select_account"
        startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(u)))
    }
    fun handleCallback(u:Uri) {
        if(u.scheme!="cyclothone"||u.host!="developer"||u.path!="/callback")return
        val returned=u.getQueryParameter("state");val expected=prefs.getString(STATE,null);val v=prefs.getString(VERIFIER,null)
        if(u.getQueryParameter("error")!=null){clearOAuth();showEntry();status.text=u.getQueryParameter("error_description")?:"Authentication cancelled.";return}
        val code=u.getQueryParameter("code")
        if(code.isNullOrBlank()||expected.isNullOrBlank()||v.isNullOrBlank()||returned!=expected){clearOAuth();showEntry();status.text="Secure sign-in could not be verified.";return}
        status.text="Completing secure sign-in..."
        thread { try {
            val body="auth_code="+enc(code)+"&code_verifier="+enc(v)
            val j=JSONObject(post(SUPABASE_URL+"/auth/v1/token?grant_type=pkce",body,"application/x-www-form-urlencoded",mapOf("apikey" to SUPABASE_KEY)))
            val t=j.optString("access_token");if(t.isBlank())throw IllegalStateException("Authentication returned no active session.")
            prefs.edit().putString(ENCRYPTED_TOKEN,sessionCrypto.encrypt(t)).remove(TOKEN).apply();clearOAuth();runOnUiThread{showPortal()}
        } catch(e:Exception){clearOAuth();runOnUiThread{showEntry();status.text=e.message?:"Authentication failed."}}}
    }
    fun clearOAuth(){prefs.edit().remove(STATE).remove(VERIFIER).apply()}

    fun showPortal() {
        val r=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(28,36,28,28)}
        r.addView(TextView(this).apply{text="Developer Portal";textSize=24f})
        status=TextView(this).apply{text="Loading live applications...";setPadding(0,10,0,16)};r.addView(status)
        list=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL};r.addView(list)
        r.addView(Button(this).apply{text="Refresh";setOnClickListener{loadApps()}})
        r.addView(Button(this).apply{text="Create application";setOnClickListener{createApp()}})
        r.addView(Button(this).apply{text="Mobile Intelligence";setOnClickListener{intelligence()}})
        r.addView(Button(this).apply{text="Sign out";setOnClickListener{prefs.edit().remove(TOKEN).remove(ENCRYPTED_TOKEN).apply();showEntry()}})
        setContentView(r);loadApps()
    }
    fun token():String = prefs.getString(ENCRYPTED_TOKEN,null)?.let { runCatching { sessionCrypto.decrypt(it) }.getOrNull() }
        ?: prefs.getString(TOKEN,null)?.also { prefs.edit().putString(ENCRYPTED_TOKEN,sessionCrypto.encrypt(it)).remove(TOKEN).apply() }
        ?: throw IllegalStateException("Authentication session is missing.")
    fun loadApps(){thread{try{
        val j=JSONObject(get("/api/v1/developer/apps"));val a=j.optJSONArray("applications")?:j.optJSONArray("apps")?:JSONArray()
        runOnUiThread{list.removeAllViews();status.text=a.length().toString()+" application(s)"
            for(i in 0 until a.length()){val x=a.getJSONObject(i);list.addView(Button(this).apply{text=x.optString("name","Application");setOnClickListener{keys(x.optString("id"))}})}
        }
    }catch(e:Exception){runOnUiThread{status.text=e.message?:"Unable to load applications."}}}}
    fun createApp(){val input=EditText(this).apply{hint="Application name"};AlertDialog.Builder(this).setTitle("Create application").setView(input).setPositiveButton("Create"){_,_->thread{try{postJson("/api/v1/developer/apps",JSONObject().put("name",input.text.toString().trim()).put("allowed_scopes",JSONArray()).toString());runOnUiThread{loadApps()}}catch(e:Exception){runOnUiThread{status.text=e.message?:"Create failed."}}}}.setNegativeButton("Cancel",null).show()}
    fun keys(id:String){thread{try{val j=JSONObject(get("/api/v1/developer/apps/"+id+"/keys"));val a=j.optJSONArray("keys")?:j.optJSONArray("credentials")?:JSONArray();runOnUiThread{AlertDialog.Builder(this).setTitle("API credentials").setMessage(if(a.length()==0)"No credentials found." else (0 until a.length()).joinToString("\\n"){a.getJSONObject(it).optString("key_prefix")}).setPositiveButton("Issue"){_,_->issue(id)}.setNegativeButton("Close",null).show()}}catch(e:Exception){runOnUiThread{status.text=e.message?:"Unable to load credentials."}}}}
    fun issue(id:String){val input=EditText(this).apply{hint="Scopes, comma separated"};AlertDialog.Builder(this).setTitle("Issue API credential").setView(input).setPositiveButton("Issue"){_,_->thread{try{val s=JSONArray(input.text.toString().split(",").map{it.trim()}.filter{it.isNotEmpty()});val j=JSONObject(postJson("/api/v1/developer/apps/"+id+"/keys",JSONObject().put("scopes",s).toString()));val secret=j.optString("api_key").ifBlank{j.optString("key")};if(secret.isBlank())throw IllegalStateException("The Developer API did not return the one-time secret.");runOnUiThread{AlertDialog.Builder(this).setTitle("One-time API secret").setMessage(secret).setPositiveButton("Done",null).show()}}catch(e:Exception){runOnUiThread{status.text=e.message?:"Credential issuance failed."}}}}.setNegativeButton("Cancel",null).show()}
    fun intelligence(){val input=EditText(this).apply{hint="Approved intelligence query";minLines=3};AlertDialog.Builder(this).setTitle("Mobile Intelligence").setView(input).setPositiveButton("Run"){_,_->thread{try{val out=postJson("/api/v1/mobile-intelligence/query",JSONObject().put("query",input.text.toString()).toString());runOnUiThread{AlertDialog.Builder(this).setTitle("Live result").setMessage(out).setPositiveButton("Done",null).show()}}catch(e:Exception){runOnUiThread{status.text=e.message?:"Query failed."}}}}.setNegativeButton("Cancel",null).show()}
    fun get(path:String)=request("GET",API_BASE+path,null)
    fun postJson(path:String,body:String)=post(API_BASE+path,body,"application/json",mapOf("Authorization" to "Bearer "+token(),"Accept" to "application/json"))
    fun post(url:String,body:String,type:String,headers:Map<String,String>):String{val c=(URL(url).openConnection() as HttpURLConnection).apply{requestMethod="POST";doOutput=true;connectTimeout=15000;readTimeout=15000;setRequestProperty("Content-Type",type);headers.forEach{(k,v)->setRequestProperty(k,v)}};c.outputStream.use{it.write(body.toByteArray())};return read(c)}
    fun request(method:String,url:String,body:String?):String{val c=(URL(url).openConnection() as HttpURLConnection).apply{requestMethod=method;connectTimeout=15000;readTimeout=15000;setRequestProperty("Authorization","Bearer "+token());setRequestProperty("Accept","application/json")};return read(c)}
    fun read(c:HttpURLConnection):String{val b=(if(c.responseCode in 200..299)c.inputStream else c.errorStream).bufferedReader().use{it.readText()};if(c.responseCode !in 200..299){val j=runCatching{JSONObject(b)}.getOrNull();throw IllegalStateException(j?.optString("detail")?.ifBlank{null}?:j?.optString("message")?.ifBlank{null}?:j?.optString("error")?.ifBlank{null}?:"API request failed ("+c.responseCode+")")};return b}
}