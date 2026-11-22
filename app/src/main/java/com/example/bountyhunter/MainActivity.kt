package com.example.bountyhunter

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

data class VulnerabilityFinding(
    val title: String,
    val severity: String, // HIGH, MEDIUM, LOW, INFO
    val endpoint: String,
    val summary: String,
    val evidence: String,
    val reproCommand: String,
    val remediation: String
)

class MainActivity : Activity() {

    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var programInput: EditText
    private lateinit var targetInput: EditText
    private lateinit var scopeCheckBox: CheckBox
    private lateinit var scanButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var liveLogText: TextView
    private lateinit var findingsContainer: LinearLayout
    private lateinit var generateReportBtn: Button

    private val findings = mutableListOf<VulnerabilityFinding>()
    private val discoveredSubdomains = mutableListOf<String>()
    private var lastScannedTarget = ""
    private var lastProgramName = ""
    private var isScanning = false

    // Hacker-Terminal Cyber Palette
    private val bgDark = Color.parseColor("#090D16")
    private val cardBg = Color.parseColor("#111827")
    private val inputBg = Color.parseColor("#1F2937")
    private val borderColor = Color.parseColor("#374151")
    private val neonGreen = Color.parseColor("#10B981")
    private val cyanAccent = Color.parseColor("#06B6D4")
    private val highColor = Color.parseColor("#EF4444")
    private val medColor = Color.parseColor("#F59E0B")
    private val lowColor = Color.parseColor("#3B82F6")
    private val infoColor = Color.parseColor("#9CA3AF")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildDashboardUI()
    }

    private fun buildDashboardUI() {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(bgDark)
            isFillViewport = true
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 36, 32, 48)
        }

        // Header
        val badge = TextView(this).apply {
            text = "AUTOMATED RECON & REPORT ENGINE"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(neonGreen)
        }

        val title = TextView(this).apply {
            text = "BountyScope Studio"
            textSize = 28f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(0, 4, 0, 6)
        }

        val subtitle = TextView(this).apply {
            text = "Automated subdomain discovery, header/CORS/TLS auditing, and one-tap Markdown report generation."
            textSize = 13f
            setTextColor(Color.LTGRAY)
            setPadding(0, 0, 0, 22)
        }

        root.addView(badge)
        root.addView(title)
        root.addView(subtitle)

        // Target Configuration Card
        val configCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            background = roundedBox(cardBg, borderColor, 2, 20f)
        }

        val programLabel = TextView(this).apply {
            text = "BUG BOUNTY PROGRAM NAME"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(cyanAccent)
        }

        programInput = EditText(this).apply {
            hint = "e.g., HackerOne - Example Corp VDP"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(22, 16, 22, 16)
            background = roundedBox(inputBg, borderColor, 1, 14f)
        }

        val targetLabel = TextView(this).apply {
            text = "IN-SCOPE TARGET DOMAIN"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(cyanAccent)
            setPadding(0, 16, 0, 0)
        }

        targetInput = EditText(this).apply {
            hint = "e.g., example.com (without https://)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(22, 16, 22, 16)
            background = roundedBox(inputBg, borderColor, 1, 14f)
        }

        scopeCheckBox = CheckBox(this).apply {
            text = "I confirm this target is explicitly in scope of an authorized bug bounty program."
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(8, 16, 8, 12)
        }

        scanButton = Button(this).apply {
            text = "▶ RUN AUTOMATED RECON & VULN SCAN"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
            setPadding(20, 22, 20, 22)
            background = roundedBox(neonGreen, neonGreen, 0, 16f)
            setOnClickListener { startAutomatedScan() }
        }

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = true
            visibility = ProgressBar.GONE
            setPadding(0, 14, 0, 0)
        }

        val fieldParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 6, 0, 6) }

        configCard.addView(programLabel)
        configCard.addView(programInput, fieldParams)
        configCard.addView(targetLabel)
        configCard.addView(targetInput, fieldParams)
        configCard.addView(scopeCheckBox)
        configCard.addView(scanButton, fieldParams)
        configCard.addView(progressBar)

        val cardSpacing = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, 20) }
        root.addView(configCard, cardSpacing)

        // Live Terminal Console Card
        val consoleCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(22, 18, 22, 18)
            background = roundedBox(Color.parseColor("#05080F"), borderColor, 1, 16f)
        }

        val consoleHeader = TextView(this).apply {
            text = "LIVE SCANNER TELEMETRY"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(neonGreen)
            setPadding(0, 0, 0, 8)
        }

        liveLogText = TextView(this).apply {
            text = "[READY] Enter an authorized domain above to begin automated recon..."
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#D1D5DB"))
        }

        consoleCard.addView(consoleHeader)
        consoleCard.addView(liveLogText)
        root.addView(consoleCard, cardSpacing)

        // Generate Report Button
        generateReportBtn = Button(this).apply {
            text = "📄 GENERATE & EXPORT FULL BOUNTY REPORT"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(20, 22, 20, 22)
            background = roundedBox(cyanAccent, cyanAccent, 0, 16f)
            isEnabled = false
            alpha = 0.45f
            setOnClickListener { showFullReportModal() }
        }
        root.addView(generateReportBtn, cardSpacing)

        // Findings Section Header
        val findingsHeader = TextView(this).apply {
            text = "DETECTED FINDINGS & MISCONFIGURATIONS"
            textSize = 13f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(4, 4, 4, 12)
        }
        root.addView(findingsHeader)

        findingsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(findingsContainer)

        scroll.addView(root)
        setContentView(scroll)
    }

    private fun startAutomatedScan() {
        if (isScanning) return

        val rawTarget = targetInput.text.toString().trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .trimEnd('/')

        if (rawTarget.isBlank() || !rawTarget.contains(".")) {
            toast("Enter a valid domain (e.g., example.com)")
            return
        }

        if (!scopeCheckBox.isChecked) {
            toast("Please confirm target authorization scope first.")
            return
        }

        isScanning = true
        findings.clear()
        discoveredSubdomains.clear()
        findingsContainer.removeAllViews()
        lastScannedTarget = rawTarget
        lastProgramName = programInput.text.toString().trim().ifEmpty { "Authorized Bug Bounty Program" }

        scanButton.isEnabled = false
        scanButton.text = "SCANNING TARGET..."
        progressBar.visibility = ProgressBar.VISIBLE
        generateReportBtn.isEnabled = false
        generateReportBtn.alpha = 0.45f
        liveLogText.text = ""

        executor.execute {
            try {
                logLine("[1/6] Querying Certificate Transparency logs (crt.sh) for *.$rawTarget...")
                enumerateSubdomains(rawTarget)

                val targetUrl = "https://$rawTarget"
                logLine("[2/6] Inspecting TLS certificate & HTTPS response on $targetUrl...")
                auditTlsAndHeaders(targetUrl, rawTarget)

                logLine("[3/6] Probing CORS policy reflection...")
                auditCorsPolicy(targetUrl)

                logLine("[4/6] Checking security disclosure & crawler files...")
                auditWellKnownFiles(targetUrl)

                logLine("[5/6] Checking for exposed Git repository metadata...")
                auditGitExposure(targetUrl)

                logLine("[6/6] Compiling vulnerability findings & CVSS severity...")
                mainHandler.post {
                    finishScanUI()
                }
            } catch (e: Exception) {
                logLine("[ERROR] Scan interrupted: ${e.message}")
                mainHandler.post {
                    isScanning = false
                    scanButton.isEnabled = true
                    scanButton.text = "▶ RUN AUTOMATED RECON & VULN SCAN"
                    progressBar.visibility = ProgressBar.GONE
                }
            }
        }
    }

    // ==================== RECON & VULNERABILITY MODULES ====================

    private fun enumerateSubdomains(domain: String) {
        try {
            val encoded = URLEncoder.encode("%.$domain", "UTF-8")
            val url = URL("https://crt.sh/?q=$encoded&output=json")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 9000
                readTimeout = 9000
                setRequestProperty("User-Agent", "BountyScopeStudio/1.0")
            }

            if (conn.responseCode == 200) {
                val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                val jsonArray = JSONArray(body)
                val uniqueHosts = sortedSetOf<String>()

                for (i in 0 until minOf(jsonArray.length(), 400)) {
                    val nameValue = jsonArray.getJSONObject(i).optString("name_value", "")
                    nameValue.split("\n").forEach { entry ->
                        val clean = entry.trim().lowercase(Locale.US).removePrefix("*.")
                        if (clean.endsWith(domain) && clean != domain) {
                            uniqueHosts.add(clean)
                        }
                    }
                }

                discoveredSubdomains.addAll(uniqueHosts.take(40))
                logLine("   ↳ Discovered ${uniqueHosts.size} unique subdomains.")

                if (uniqueHosts.isNotEmpty()) {
                    val sampleList = discoveredSubdomains.take(15).joinToString("\n")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Subdomain Attack Surface Enumerated (${uniqueHosts.size} Hosts)",
                            severity = "INFO",
                            endpoint = "*.$domain",
                            summary = "Public Certificate Transparency logs exposed ${uniqueHosts.size} subdomains associated with$domain. Secondary/staging hosts often carry weaker security controls.",
                            evidence = "Sample Discovered Subdomains:\n$sampleList",
                            reproCommand = "curl -s \"https://crt.sh/?q=%25.$domain&output=json\" | jq -r '.[].name_value' | sort -u",
                            remediation = "Audit all enumerated subdomains for orphaned DNS records (Subdomain Takeover) and restrict staging/internal hosts behind VPN or IP allowlists."
                        )
                    )
                }
            }
            conn.disconnect()
        } catch (e: Exception) {
            logLine("   ↳ CT log lookup skipped (${e.javaClass.simpleName}).")
        }
    }

    private fun auditTlsAndHeaders(targetUrl: String, domain: String) {
        try {
            val conn = (URL(targetUrl).openConnection() as HttpsURLConnection).apply {
                instanceFollowRedirects = true
                connectTimeout = 8000
                readTimeout = 8000
                setRequestProperty("User-Agent", "Mozilla/5.0 BountyScopeAudit/1.0")
            }

            val status = conn.responseCode
            val headers = conn.headerFields
            logLine("   ↳ Connected (HTTP $status). Analyzing security headers & TLS...")

            // Check TLS Certificate Expiration
            try {
                val certs = conn.serverCertificates
                if (certs.isNotEmpty() && certs[0] is X509Certificate) {
                    val x509 = certs[0] as X509Certificate
                    val daysLeft = (x509.notAfter.time - System.currentTimeMillis()) / (1000 * 60 * 60 * 24)
                    if (daysLeft < 14) {
                        addFinding(
                            VulnerabilityFinding(
                                title = "TLS Certificate Expiring Soon ($daysLeft Days Left)",
                                severity = "LOW",
                                endpoint = targetUrl,
                                summary = "The TLS certificate for $domain expires on${x509.notAfter}.",
                                evidence = "Subject: ${x509.subjectDN}\nExpires:${x509.notAfter}",
                                reproCommand = "openssl s_client -connect $domain:443 </dev/null 2>/dev/null | openssl x509 -noout -dates",
                                remediation = "Renew the TLS certificate and enable automated ACME/Let's Encrypt renewal."
                            )
                        )
                    }
                }
            } catch (_: Exception) {
            }

            fun getHeader(name: String): String? {
                return headers.entries.firstOrNull { it.key != null && it.key.equals(name, ignoreCase = true) }
                    ?.value?.joinToString("; ")
            }

            // 1. HSTS Check
            val hsts = getHeader("Strict-Transport-Security")
            if (hsts == null) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing HTTP Strict Transport Security (HSTS)",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "The application does not send a Strict-Transport-Security header, allowing potential SSL-stripping on first visit over untrusted networks.",
                        evidence = "HTTP $status response lacked 'Strict-Transport-Security'.",
                        reproCommand = "curl -I -s $targetUrl | grep -i strict-transport-security",
                        remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
                    )
                )
            }

            // 2. Clickjacking (X-Frame-Options / CSP frame-ancestors)
            val xfo = getHeader("X-Frame-Options")
            val csp = getHeader("Content-Security-Policy")
            val hasFrameAncestors = csp?.contains("frame-ancestors", ignoreCase = true) == true
            if (xfo == null && !hasFrameAncestors) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing Anti-Clickjacking Protection (X-Frame-Options / CSP)",
                        severity = "MEDIUM",
                        endpoint = targetUrl,
                        summary = "Neither X-Frame-Options nor CSP frame-ancestors is configured, enabling attackers to embed sensitive pages inside an invisible iframe for UI redressing.",
                        evidence = "X-Frame-Options: <missing>\nContent-Security-Policy: ${csp ?: "<missing>"}",
                        reproCommand = "curl -I -s $targetUrl | grep -iE \"x-frame-options|content-security-policy\"",
                        remediation = "Set 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: SAMEORIGIN'."
                    )
                )
            }

            // 3. Content-Security-Policy Check
            if (csp == null) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing Content-Security-Policy (CSP) Header",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "No Content-Security-Policy header is enforced, increasing the exploitability impact of any Cross-Site Scripting (XSS) vulnerability.",
                        evidence = "HTTP $status response contained no Content-Security-Policy header.",
                        reproCommand = "curl -I -s $targetUrl | grep -i content-security-policy",
                        remediation = "Implement a restrictive Content-Security-Policy with nonce-based script execution and explicit default-src 'self'."
                    )
                )
            }

            // 4. X-Content-Type-Options
            val xcto = getHeader("X-Content-Type-Options")
            if (xcto == null || !xcto.equals("nosniff", ignoreCase = true)) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing X-Content-Type-Options: nosniff",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "Browsers may MIME-sniff responses away from the declared Content-Type, risking script execution on user-uploaded files.",
                        evidence = "X-Content-Type-Options: ${xcto ?: "<missing>"}",
                        reproCommand = "curl -I -s $targetUrl | grep -i x-content-type-options",
                        remediation = "Set 'X-Content-Type-Options: nosniff' across all HTTP responses."
                    )
                )
            }

            // 5. Server Version Disclosure
            val serverHeader = getHeader("Server")
            val poweredBy = getHeader("X-Powered-By")
            if ((serverHeader != null && serverHeader.any { it.isDigit() }) || poweredBy != null) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Server & Technology Version Disclosure",
                        severity = "INFO",
                        endpoint = targetUrl,
                        summary = "Response headers disclose specific backend software versions, aiding attackers in mapping known CVEs.",
                        evidence = "Server: ${serverHeader ?: "N/A"}\nX-Powered-By: ${poweredBy ?: "N/A"}",
                        reproCommand = "curl -I -s $targetUrl | grep -iE \"server:|x-powered-by:\"",
                        remediation = "Strip version numbers from the Server banner and remove X-Powered-By headers in reverse-proxy/server configuration."
                    )
                )
            }

            // 6. Cookie Security Flags
            val cookies = headers.entries.firstOrNull { it.key != null && it.key.equals("Set-Cookie", ignoreCase = true) }?.value
            cookies?.forEach { cookie ->
                val missingFlags = mutableListOf<String>()
                if (!cookie.contains("Secure", ignoreCase = true)) missingFlags.add("Secure")
                if (!cookie.contains("HttpOnly", ignoreCase = true)) missingFlags.add("HttpOnly")
                if (!cookie.contains("SameSite", ignoreCase = true)) missingFlags.add("SameSite")

                if (missingFlags.isNotEmpty()) {
                    val cookieName = cookie.substringBefore("=")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Insecure Cookie Attributes on '$cookieName'",
                            severity = "MEDIUM",
                            endpoint = targetUrl,
                            summary = "Cookie '$cookieName' is missing security flags (${missingFlags.joinToString(", ")}), exposing it to XSS theft or CSRF replay.",
                            evidence = "Set-Cookie: ${cookie.take(120)}",
                            reproCommand = "curl -I -s $targetUrl | grep -i set-cookie",
                            remediation = "Append '; Secure; HttpOnly; SameSite=Lax' to all sensitive cookies."
                        )
                    )
                }
            }

            conn.disconnect()
        } catch (e: Exception) {
            logLine("   ↳ HTTPS audit failed: ${e.message}")
        }
    }

    private fun auditCorsPolicy(targetUrl: String) {
        val evilOrigin = "https://evil-attacker.example"
        try {
            val conn = (URL(targetUrl).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 7000
                readTimeout = 7000
                setRequestProperty("Origin", evilOrigin)
                setRequestProperty("User-Agent", "BountyScopeAudit/1.0")
            }

            val acao = conn.getHeaderField("Access-Control-Allow-Origin")
            val acac = conn.getHeaderField("Access-Control-Allow-Credentials")

            if (acao != null && acao.equals(evilOrigin, ignoreCase = true)) {
                val withCreds = acac.equals("true", ignoreCase = true)
                addFinding(
                    VulnerabilityFinding(
                        title = if (withCreds)
                            "Critical CORS Arbitrary Origin Reflection with Credentials"
                        else
                            "Permissive CORS Arbitrary Origin Reflection",
                        severity = if (withCreds) "HIGH" else "MEDIUM",
                        endpoint = targetUrl,
                        summary = "The endpoint dynamically reflects arbitrary Origin headers in Access-Control-Allow-Origin" +
                            if (withCreds) " with Access-Control-Allow-Credentials: true, allowing cross-origin authenticated data theft." else ".",
                        evidence = "Request Origin: $evilOrigin\nAccess-Control-Allow-Origin: $acao\nAccess-Control-Allow-Credentials:${acac ?: "false"}",
                        reproCommand = "curl -I -s -H \"Origin: $evilOrigin\" $targetUrl | grep -i access-control",
                        remediation = "Validate the Origin header against a strict server-side allowlist of trusted domains instead of reflecting arbitrary origins."
                    )
                )
                logLine("   ↳ [!] CORS origin reflection detected!")
            } else {
                logLine("   ↳ CORS origin check clean.")
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
    }

    private fun auditWellKnownFiles(targetUrl: String) {
        try {
            val secUrl = "$targetUrl/.well-known/security.txt"
            val conn = (URL(secUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 6000
                readTimeout = 6000
            }
            if (conn.responseCode == 200) {
                val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                if (body.contains("Contact:", ignoreCase = true)) {
                    logLine("   ↳ Verified /.well-known/security.txt disclosure policy.")
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
    }

    private fun auditGitExposure(targetUrl: String) {
        try {
            val gitUrl = "$targetUrl/.git/HEAD"
            val conn = (URL(gitUrl).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 6000
                readTimeout = 6000
            }
            if (conn.responseCode == 200) {
                val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText().trim() }
                // Strict validation to avoid false positives on custom 200 HTML pages
                if (body.startsWith("ref: refs/")) {
                    addFinding(
                        VulnerabilityFinding(
                            title = "Exposed .git Repository Metadata (/.git/HEAD)",
                            severity = "HIGH",
                            endpoint = gitUrl,
                            summary = "The web root publicly serves the .git/HEAD file, potentially allowing full source code and commit history reconstruction.",
                            evidence = "GET $gitUrl -> HTTP 200\nBody:$body",
                            reproCommand = "curl -s $gitUrl",
                            remediation = "Block public web server access to all dotfiles/directories (e.g., 'location ~ /\\. { deny all; }' in Nginx)."
                        )
                    )
                    logLine("   ↳ [!] HIGH: Exposed .git/HEAD detected!")
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
    }
     // ==================== UI RENDERING & REPORT BUILDER ====================

    private fun addFinding(finding: VulnerabilityFinding) {
        findings.add(finding)
        mainHandler.post {
            renderFindingCard(finding)
        }
    }

    private fun renderFindingCard(f: VulnerabilityFinding) {
        val badgeColor = when (f.severity) {
            "HIGH" -> highColor
            "MEDIUM" -> medColor
            "LOW" -> lowColor
            else -> infoColor
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(22, 18, 22, 18)
            background = roundedBox(cardBg, badgeColor, 2, 16f)
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val sevPill = TextView(this).apply {
            text = f.severity
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
            setPadding(16, 4, 16, 4)
            background = roundedBox(badgeColor, badgeColor, 0, 20f)
        }

        val endpointTxt = TextView(this).apply {
            text = "  ${f.endpoint}"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.GRAY)
            maxLines = 1
        }

        topRow.addView(sevPill)
        topRow.addView(endpointTxt)

        val titleTxt = TextView(this).apply {
            text = f.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(0, 10, 0, 6)
        }

        val summaryTxt = TextView(this).apply {
            text = f.summary
            textSize = 12f
            setTextColor(Color.LTGRAY)
        }

        val viewSingleBtn = Button(this).apply {
            text = "VIEW & COPY SINGLE REPORT"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(cyanAccent)
            background = roundedBox(inputBg, borderColor, 1, 12f)
            setOnClickListener {
                showSingleFindingReport(f)
            }
        }

        val btnMargin = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 14, 0, 0) }

        card.addView(topRow)
        card.addView(titleTxt)
        card.addView(summaryTxt)
        card.addView(viewSingleBtn, btnMargin)

        val cardMargin = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, 14) }

        findingsContainer.addView(card, cardMargin)
    }

    private fun finishScanUI() {
        isScanning = false
        scanButton.isEnabled = true
        scanButton.text = "▶ RUN AUTOMATED RECON & VULN SCAN"
        progressBar.visibility = ProgressBar.GONE

        logLine("[DONE] Scan finished. Total findings logged: ${findings.size}")

        if (findings.isNotEmpty()) {
            generateReportBtn.isEnabled = true
            generateReportBtn.alpha = 1.0f
        } else {
            val cleanTxt = TextView(this).apply {
                text = "No misconfigurations or exposed files detected on $lastScannedTarget."
                textSize = 13f
                setTextColor(neonGreen)
                setPadding(12, 12, 12, 12)
            }
            findingsContainer.addView(cleanTxt)
        }
    }

    private fun buildMarkdownReport(items: List<VulnerabilityFinding>): String {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date())
        val sb = StringBuilder()

        sb.appendLine("# Security Assessment & Bug Bounty Report")
        sb.appendLine("- **Program:** $lastProgramName")
        sb.appendLine("- **Target Asset:** `$lastScannedTarget`")
        sb.appendLine("- **Date:** $timestamp")
        sb.appendLine("- **Total Findings:** ${items.size}")
        sb.appendLine("\n---\n")

        items.forEachIndexed { idx, f ->
            sb.appendLine("## ${idx + 1}. [${f.severity}]${f.title}")
            sb.appendLine("**Affected Endpoint:** `${f.endpoint}`\n")
            sb.appendLine("### Summary")
            sb.appendLine("${f.summary}\n")
            sb.appendLine("### Steps to Reproduce")
            sb.appendLine("1. Open a terminal or HTTP proxy.")
            sb.appendLine("2. Run the verification request below:")
            sb.appendLine("```bash")
            sb.appendLine(f.reproCommand)
            sb.appendLine("```\n")
            sb.appendLine("### Captured Evidence")
            sb.appendLine("```text")
            sb.appendLine(f.evidence)
            sb.appendLine("```\n")
            sb.appendLine("### Remediation")
            sb.appendLine("${f.remediation}\n")
            sb.appendLine("---\n")
        }

        return sb.toString()
    }
    private fun showSingleFindingReport(finding: VulnerabilityFinding) {
        val md = buildMarkdownReport(listOf(finding))
        showReportDialog(finding.title, md)
    }

    private fun showFullReportModal() {
        val md = buildMarkdownReport(findings)
        showReportDialog("Full Bounty Report ($lastScannedTarget)", md)
    }

    private fun showReportDialog(dialogTitle: String, markdownContent: String) {
        val scroll = ScrollView(this).apply {
            setPadding(36, 24, 36, 24)
        }
        val reportText = TextView(this).apply {
            text = markdownContent
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        scroll.addView(reportText)

        AlertDialog.Builder(this)
            .setTitle(dialogTitle)
            .setView(scroll)
            .setPositiveButton("COPY MARKDOWN") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Bug Bounty Report", markdownContent))
                toast("Markdown report copied to clipboard!")
            }
            .setNeutralButton("SHARE / EXPORT") { _, _ ->
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "Bug Bounty Report - $lastScannedTarget")
                    putExtra(Intent.EXTRA_TEXT, markdownContent)
                }
                startActivity(Intent.createChooser(shareIntent, "Export Vulnerability Report"))
            }
            .setNegativeButton("CLOSE", null)
            .show()
    }

    private fun logLine(message: String) {
        mainHandler.post {
            val current = liveLogText.text.toString()
            liveLogText.text = if (current.isEmpty()) message else "$current\n$message"
        }
    }

    private fun roundedBox(
        fillColor: Int,
        strokeColor: Int,
        strokeWidthDp: Int,
        radiusDp: Float
    ): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = radiusDp * resources.displayMetrics.density
            setColor(fillColor)
            if (strokeWidthDp > 0) {
                setStroke((strokeWidthDp * resources.displayMetrics.density).toInt(), strokeColor)
            }
        }
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        executor.shutdownNow()
        super.onDestroy()
    }
}
