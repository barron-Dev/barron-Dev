package online.cyclothone.mobile

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.UUID
import kotlin.concurrent.thread

class DeveloperActivity : Activity() {
    companion object {
        private const val SUPABASE_URL = "https://whcomikcftbousoqzeal.supabase.co"
        private const val API_BASE = "https://cyclothone-api-production.up.railway.app"
        private const val REDIRECT_URI = "cyclothone://developer/callback"
        private const val KEY = "developer_access_token"
    }
    private val prefs by lazy { getSharedPreferences("cyclothone_developer", MODE_PRIVATE) }
    private lateinit var status: TextView
    private var token: String? = null
    private var selectedAppId: String? = null
    private var apps = JSONArray()
    private var keys = JSONArray()

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        token = prefs.getString(KEY, null)
        if (intent?.data != null) handleCallback(intent.data!!)
        else if (!token.isNullOrBlank()) showPortal()
        else showSignIn()
    }

    private fun base(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER
        setPadding(40, 40, 40, 40)
        setBackgroundColor(Color.rgb(4, 16, 27))
    }

    private fun showSignIn() {
        val root = base()
        val title = TextView(this).apply { text = "CYCLOTHONE"; textSize = 26f; setTextColor(Color.WHITE); gravity = Gravity.CENTER }
        status = TextView(this).apply { text = "Developer access"; textSize = 14f; setTextColor(Color.LTGRAY); gravity = Gravity.CENTER; setPadding(0, 12, 0, 24) }
        val google = Button(this).apply { text = "Sign in with Google"; setOnClickListener { startOAuth("google") } }
        val github = Button(this).apply { text = "Continue with GitHub"; setOnClickListener { startOAuth("github") } }
        root.addView(title); root.addView(status); root.addView(google); root.addView(github)
        setContentView(root)
    }

    private fun startOAuth(provider: String) {
        val state = UUID.randomUUID().toString()
        prefs.edit().putString("oauth_state", state).apply()
        val url = "$SUPABASE_URL/auth/v1/authorize?provider=\${enc(provider)}&redirect_to=\${enc(REDIRECT_URI)}&state=\${enc(state)}&prompt=select_account"
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }

    private fun handleCallback(uri: Uri) {
        if (uri.scheme != "cyclothone" || uri.host != "developer" || uri.path != "/callback") return
        val expectedState = prefs.getString("oauth_state", null)
        val returnedState = uri.getQueryParameter("state")
        if (expectedState.isNullOrBlank() || returnedState.isNullOrBlank() || expectedState != returnedState) {
            prefs.edit().remove("oauth_state").apply()
            showSignIn()
            status.text = "Developer sign-in failed: invalid OAuth state."
            return
        }
        val access = uri.fragment.orEmpty().split("&").mapNotNull {
            val p = it.split("=", limit = 2)
            if (p.size == 2) p[0] to java.net.URLDecoder.decode(p[1], "UTF-8") else null
        }.toMap()["access_token"]
        if (!access.isNullOrBlank()) {
            token = access
            prefs.edit().putString(KEY, access).remove("oauth_state").apply()
            showPortal()
            return
        }
        showSignIn()
        status.text = uri.getQueryParameter("error_description") ?: "Developer sign-in failed."
    }

    private fun showPortal() {
        val root = base().apply { gravity = Gravity.TOP }
        status = TextView(this).apply { text = "Developer"; textSize = 22f; setTextColor(Color.WHITE); setPadding(0, 0, 0, 10) }
        val info = TextView(this).apply { text = "Applications and API credentials"; textSize = 13f; setTextColor(Color.LTGRAY); setPadding(0, 0, 0, 18) }
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val refresh = Button(this).apply { text = "Refresh"; setOnClickListener { loadApps(list) } }
        val create = Button(this).apply { text = "Create application"; setOnClickListener { createApplication(list) } }
        val issue = Button(this).apply { text = "Issue API credential"; setOnClickListener {
            val id = selectedAppId
            if (id == null) status.text = "Select an application first." else issueCredential(id, list)
        }}
        val intelligence = Button(this).apply { text = "Query Mobile Intelligence"; setOnClickListener { queryIntelligence() } }
        val signOut = Button(this).apply { text = "Sign out"; setOnClickListener { prefs.edit().remove(KEY).apply(); token = null; showSignIn() } }
        root.addView(status); root.addView(info); root.addView(refresh); root.addView(create); root.addView(issue); root.addView(intelligence); root.addView(list); root.addView(signOut)
        setContentView(root)
        loadApps(list)
    }

    private fun loadApps(container: LinearLayout) {
        val t = token ?: return
        status.text = "Loading live applications…"
        thread {
            try {
                val body = api("GET", "/api/v1/developer/apps", null, t)
                apps = if (body.trimStart().startsWith("[")) JSONArray(body) else JSONObject(body).optJSONArray("applications") ?: JSONArray()
                runOnUiThread {
                    container.removeAllViews()
                    for (i in 0 until apps.length()) {
                        val app = apps.getJSONObject(i)
                        val b = Button(this).apply {
                            text = "\${app.optString("name")} · \${if (app.optBoolean("active", true)) "Active" else "Inactive"}"
                            setOnClickListener { selectedAppId = app.optString("id"); status.text = "Selected: \${app.optString("name")}"; loadKeys(selectedAppId!!, container) }
                        }
                        container.addView(b)
                    }
                    status.text = "Live developer data loaded."
                }
            } catch (e: Exception) { runOnUiThread { status.text = e.message ?: "Developer API failed." } }
        }
    }

    private fun loadKeys(appId: String, container: LinearLayout) {
        val t = token ?: return
        thread {
            try {
                val body = api("GET", "/api/v1/developer/apps/$appId/keys", null, t)
                keys = if (body.trimStart().startsWith("[")) JSONArray(body) else JSONObject(body).optJSONArray("keys") ?: JSONArray()
                runOnUiThread {
                    for (i in 0 until keys.length()) {
                        val k = keys.getJSONObject(i)
                        container.addView(TextView(this).apply {
                            text = "\${k.optString("key_prefix")} · \${if (k.optBoolean("active", true)) "Active" else "Inactive"}\n\${k.optJSONArray("scopes")?.join(", ") ?: ""}"
                            setTextColor(Color.LTGRAY); setPadding(8, 8, 8, 8)
                        })
                    }
                }
            } catch (e: Exception) { runOnUiThread { status.text = e.message ?: "Credential lookup failed." } }
        }
    }

    private fun createApplication(container: LinearLayout) {
        val input = EditText(this).apply { hint = "Application name" }
        AlertDialog.Builder(this).setTitle("Create application").setView(input)
            .setPositiveButton("Create") { _, _ ->
                val name = input.text.toString().trim()
                if (name.isBlank()) { status.text = "Application name is required."; return@setPositiveButton }
                thread {
                    try {
                        api("POST", "/api/v1/developer/apps", JSONObject().apply { put("name", name); put("allowed_scopes", JSONArray()) }.toString(), token!!)
                        runOnUiThread { status.text = "Application created."; loadApps(container) }
                    } catch (e: Exception) { runOnUiThread { status.text = e.message ?: "Application creation failed." } }
                }
            }.setNegativeButton("Cancel", null).show()
    }

    private fun issueCredential(appId: String, container: LinearLayout) {
        thread {
            try {
                val body = api("POST", "/api/v1/developer/apps/$appId/keys", JSONObject().apply { put("scopes", JSONArray()) }.toString(), token!!)
                val j = JSONObject(body)
                val secret = j.optString("api_key").ifBlank { j.optString("key") }
                runOnUiThread {
                    if (secret.isBlank()) status.text = "Developer API returned no one-time secret."
                    else AlertDialog.Builder(this).setTitle("API credential issued").setMessage(secret).setPositiveButton("Done", null).show()
                    loadKeys(appId, container)
                }
            } catch (e: Exception) { runOnUiThread { status.text = e.message ?: "Credential issuance failed." } }
        }
    }

    private fun queryIntelligence() {
        val input = EditText(this).apply { hint = "Approved intelligence query" }
        AlertDialog.Builder(this).setTitle("Mobile Intelligence").setView(input)
            .setPositiveButton("Run") { _, _ ->
                val query = input.text.toString().trim()
                if (query.isBlank()) { status.text = "Query is required."; return@setPositiveButton }
                thread {
                    try {
                        val body = api("POST", "/api/v1/mobile-intelligence/query", JSONObject().apply { put("query", query) }.toString(), token!!)
                        runOnUiThread { AlertDialog.Builder(this).setTitle("Live result").setMessage(body).setPositiveButton("Done", null).show() }
                    } catch (e: Exception) { runOnUiThread { status.text = e.message ?: "Intelligence query failed." } }
                }
            }.setNegativeButton("Cancel", null).show()
    }

    private fun api(method: String, path: String, body: String?, bearer: String): String {
        val c = (URL(API_BASE + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method; connectTimeout = 15000; readTimeout = 15000
            setRequestProperty("Authorization", "Bearer $bearer"); setRequestProperty("Accept", "application/json")
            if (body != null) { doOutput = true; setRequestProperty("Content-Type", "application/json") }
        }
        if (body != null) c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        val text = (if (c.responseCode in 200..299) c.inputStream else c.errorStream).bufferedReader().use { it.readText() }
        if (c.responseCode !in 200..299) throw IllegalStateException(runCatching { JSONObject(text).optString("detail") }.getOrNull().orEmpty().ifBlank { "Developer API returned HTTP \${c.responseCode}." })
        return text
    }

    private fun enc(v: String) = URLEncoder.encode(v, Charsets.UTF_8.name())
}
