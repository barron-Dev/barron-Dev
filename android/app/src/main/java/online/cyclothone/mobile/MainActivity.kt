package online.cyclothone.mobile

import android.app.Activity
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Button

class MainActivity : Activity() {
    private val workspaceUrl = "https://customers.cyclothone.online"
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(Color.rgb(4,16,27)) }
        val title = TextView(this).apply { text = "CYCLOTHONE"; textSize = 24f; setTextColor(Color.WHITE); gravity = Gravity.CENTER; setPadding(0,32,0,16) }
        val subtitle = TextView(this).apply { text = "Secure mobile access"; textSize = 14f; setTextColor(Color.LTGRAY); gravity = Gravity.CENTER; setPadding(0,0,0,20) }
        val button = Button(this).apply { text = "Open secure workspace"; setOnClickListener { openWorkspace() } }
        root.addView(title, LinearLayout.LayoutParams(-1, -2)); root.addView(subtitle, LinearLayout.LayoutParams(-1,-2)); root.addView(button, LinearLayout.LayoutParams(-1,-2))
        setContentView(root)
    }
    private fun openWorkspace() {
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.webViewClient = WebViewClient()
        web.loadUrl(workspaceUrl)
        setContentView(web)
    }
}
