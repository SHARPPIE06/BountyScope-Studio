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
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.UUID
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

    private lateinit var scanDatabase: ScanDatabase
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var historyBadgeBtn: Button
    private lateinit var programInput: EditText
    private lateinit var targetInput: EditText
    private lateinit var wordlistInput: EditText
    private lateinit var scopeCheckBox: CheckBox
    private lateinit var scanButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var liveLogText: TextView
    private lateinit var findingsContainer: LinearLayout
    private lateinit var generateReportBtn: Button

    private val findings = Collections.synchronizedList(mutableListOf<VulnerabilityFinding>())
    private val discoveredSubdomains = Collections.synchronizedList(mutableListOf<String>())
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
    private val purpleAccent = Color.parseColor("#8B5CF6")
    private val highColor = Color.parseColor("#EF4444")
    private val medColor = Color.parseColor("#F59E0B")
    private val lowColor = Color.parseColor("#3B82F6")
    private val infoColor = Color.parseColor("#9CA3AF")

    private val defaultWordlist =
        "/admin, /swagger.json, /openapi.json, /api/v1/health, /graphql, /.env, /actuator/health, /wp-json/wp/v2/users, /server-status"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        scanDatabase = ScanDatabase(this)
        buildDashboardUI()
        refreshHistoryBadge()
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

        // Top Header + Offline SQLite History Button
        val topBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 10) }
        }

        val titleCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val badge = TextView(this).apply {
            text = "AUTOMATED RECON & REPORT ENGINE v2"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(neonGreen)
        }

        val title = TextView(this).apply {
            text = "BountyScope Studio"
            textSize = 26f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(0, 2, 0, 0)
        }

        titleCol.addView(badge)
        titleCol.addView(title)

        historyBadgeBtn = Button(this).apply {
            text = "🗄️ HISTORY (0)"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(20, 12, 20, 12)
            background = roundedBox(cardBg, purpleAccent, 2, 16f)
            setOnClickListener { showSavedReportsDialog() }
        }

        topBar.addView(titleCol)
        topBar.addView(historyBadgeBtn)
        root.addView(topBar)

        val subtitle = TextView(this).apply {
            text = "Subdomains · DNS/SPF/DMARC · TLS/Headers/CORS · Custom Wordlist Prober · Offline SQLite Reports"
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(0, 0, 0, 20)
        }
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
            setPadding(0, 14, 0, 0)
        }

        targetInput = EditText(this).apply {
            hint = "e.g., example.com (without https://)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(22, 16, 22, 16)
            background = roundedBox(inputBg, borderColor, 1, 14f)
        }

        val wordlistHeaderRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, 14, 0, 0)
        }

        val wordlistLabel = TextView(this).apply {
            text = "CUSTOM ENDPOINT WORDLIST (COMMA-SEPARATED)"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(cyanAccent)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val resetWordlistBtn = Button(this).apply {
            text = "RESET"
            textSize = 10f
            setTextColor(Color.LTGRAY)
            setPadding(14, 4, 14, 4)
            background = roundedBox(inputBg, borderColor, 1, 10f)
            setOnClickListener { wordlistInput.setText(defaultWordlist) }
        }

        wordlistHeaderRow.addView(wordlistLabel)
        wordlistHeaderRow.addView(resetWordlistBtn)

        wordlistInput = EditText(this).apply {
            setText(defaultWordlist)
            hint = "/admin, /swagger.json, /graphql, /.env"
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            minLines = 2
            maxLines = 4
            setPadding(20, 14, 20, 14)
            background = roundedBox(inputBg, borderColor, 1, 14f)
        }

        scopeCheckBox = CheckBox(this).apply {
            text = "I confirm this target is explicitly in scope of an authorized bug bounty program."
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(8, 14, 8, 12)
        }

        scanButton = Button(this).apply {
            text = "▶ RUN FULL AUTOMATED SCAN & SAVE REPORT"
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
        configCard.addView(wordlistHeaderRow)
        configCard.addView(wordlistInput, fieldParams)
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
            text = "📄 VIEW / COPY / EXPORT FULL BOUNTY REPORT"
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

        val customPaths = wordlistInput.text.toString()
            .split(",", "\n")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { if (it.startsWith("/")) it else "/$it" }
            .distinct()

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
                logLine("[1/7] Querying Certificate Transparency logs (crt.sh) for *.$rawTarget...")
                enumerateSubdomains(rawTarget)

                logLine("[2/7] Resolving DNS (A, MX, TXT) & auditing SPF/DMARC policies...")
                auditDnsAndEmailSecurity(rawTarget)

                val targetUrl = "https://$rawTarget"
                logLine("[3/7] Inspecting TLS certificate & HTTP security headers on $targetUrl...")
                auditTlsAndHeaders(targetUrl, rawTarget)

                logLine("[4/7] Probing CORS policy origin reflection...")
                auditCorsPolicy(targetUrl)

                logLine("[5/7] Checking security disclosure & .git repository exposure...")
                auditWellKnownAndGit(targetUrl)

                logLine("[6/7] Probing ${customPaths.size} custom wordlist endpoints (with Soft-404 calibration)...")
                probeCustomWordlist(targetUrl, customPaths)

                logLine("[7/7] Compiling Markdown report & saving offline to SQLite database...")
                val snapshot = findings.toList()
                val fullMarkdown = buildMarkdownReport(snapshot)
                scanDatabase.saveReport(
                    programName = lastProgramName,
                    targetDomain = lastScannedTarget,
                    findings = snapshot,
                    markdownReport = fullMarkdown
                )

                mainHandler.post {
                    refreshHistoryBadge()
                    finishScanUI()
                }
            } catch (e: Exception) {
                logLine("[ERROR] Scan interrupted: ${e.message}")
                mainHandler.post {
                    isScanning = false
                    scanButton.isEnabled = true
                    scanButton.text = "▶ RUN FULL AUTOMATED SCAN & SAVE REPORT"
                    progressBar.visibility = ProgressBar.GONE
                }
            }
        }
    }

    // ==================== 1. SUBDOMAIN ENUMERATION ====================
    private fun enumerateSubdomains(domain: String) {
        try {
            val encoded = URLEncoder.encode("%.$domain", "UTF-8")
            val url = URL("https://crt.sh/?q=$encoded&output=json")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 9000
                readTimeout = 9000
                setRequestProperty("User-Agent", "BountyScopeStudio/2.0")
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
                            summary = "Public Certificate Transparency logs exposed ${uniqueHosts.size} subdomains associated with $domain. Secondary/staging hosts often carry weaker security controls.",
                            evidence = "Sample Discovered Subdomains:\n$sampleList",
                            reproCommand = "curl -s \"https://crt.sh/?q=%25.$domain&output=json\" | jq -r '.[].name_value' | sort -u",
                            remediation = "Audit all enumerated subdomains for orphaned DNS CNAME records (Subdomain Takeover) and restrict staging hosts behind VPN or IP allowlists."
                        )
                    )
                }
            }
            conn.disconnect()
        } catch (e: Exception) {
            logLine("   ↳ CT log lookup skipped (${e.javaClass.simpleName}).")
        }
    }

    // ==================== 2. DNS & EMAIL SECURITY (A, MX, TXT, SPF, DMARC) ====================
    private fun queryGoogleDns(name: String, type: String): List<String> {
        val results = mutableListOf<String>()
        try {
            val encodedName = URLEncoder.encode(name, "UTF-8")
            val url = URL("https://dns.google/resolve?name=$encodedName&type=$type")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                connectTimeout = 6000
                readTimeout = 6000
                setRequestProperty("Accept", "application/dns-json")
            }
            if (conn.responseCode == 200) {
                val jsonText = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                val rootObj = JSONObject(jsonText)
                val answers = rootObj.optJSONArray("Answer")
                if (answers != null) {
                    for (i in 0 until answers.length()) {
                        val data = answers.getJSONObject(i).optString("data", "").trim('"')
                        if (data.isNotEmpty()) results.add(data)
                    }
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
        return results
    }

    private fun auditDnsAndEmailSecurity(domain: String) {
        val aRecords = queryGoogleDns(domain, "A")
        val mxRecords = queryGoogleDns(domain, "MX")
        val txtRecords = queryGoogleDns(domain, "TXT")
        val dmarcRecords = queryGoogleDns("_dmarc.$domain", "TXT")

        logLine("   ↳ DNS A: ${aRecords.size} | MX: ${mxRecords.size} | TXT: ${txtRecords.size} | DMARC: ${dmarcRecords.size}")

        if (aRecords.isNotEmpty() || mxRecords.isNotEmpty()) {
            addFinding(
                VulnerabilityFinding(
                    title = "DNS Infrastructure Footprint (A & MX Records)",
                    severity = "INFO",
                    endpoint = domain,
                    summary = "Resolved primary IPv4 and mail-exchanger infrastructure for $domain.",
                    evidence = "A Records: ${if (aRecords.isEmpty()) "None" else aRecords.joinToString(", ")}\n" +
                        "MX Records: ${if (mxRecords.isEmpty()) "None" else mxRecords.joinToString(", ")}",
                    reproCommand = "dig +short $domain A && dig +short $domain MX",
                    remediation = "Ensure origin IP addresses behind CDNs/WAFs are firewalled to only accept traffic from CDN edge ranges."
                )
            )
        }

        // Check SPF record
        val spfRecord = txtRecords.firstOrNull { it.contains("v=spf1", ignoreCase = true) }
        if (spfRecord == null) {
            addFinding(
                VulnerabilityFinding(
                    title = "Missing SPF Record (Email Spoofing Risk)",
                    severity = if (mxRecords.isNotEmpty()) "MEDIUM" else "LOW",
                    endpoint = "$domain (DNS TXT)",
                    summary = "No Sender Policy Framework (SPF) TXT record was found for $domain, allowing unauthorized mail servers to spoof emails from this domain.",
                    evidence = "TXT Records Returned:\n${if (txtRecords.isEmpty()) "<none>" else txtRecords.joinToString("\n")}",
                    reproCommand = "dig +short $domain TXT | grep -i spf",
                    remediation = "Publish a strict SPF TXT record ending with '-all' (e.g., 'v=spf1 include:_spf.google.com -all')."
                )
            )
        } else if (spfRecord.contains("+all", ignoreCase = true) || spfRecord.contains("?all", ignoreCase = true)) {
            addFinding(
                VulnerabilityFinding(
                    title = "Permissive SPF Policy (+all / ?all Configured)",
                    severity = "MEDIUM",
                    endpoint = "$domain (DNS TXT)",
                    summary = "The domain's SPF record uses '+all' or '?all', which authorizes or neutralizes spoofed senders instead of rejecting them.",
                    evidence = "Current SPF Record: $spfRecord",
                    reproCommand = "dig +short $domain TXT",
                    remediation = "Change the SPF qualifier from '+all' or '?all' to '-all' (hard fail)."
                )
            )
        }

        // Check DMARC record
        val dmarcRecord = dmarcRecords.firstOrNull { it.contains("v=DMARC1", ignoreCase = true) }
        if (dmarcRecord == null) {
            addFinding(
                VulnerabilityFinding(
                    title = "Missing DMARC Policy (_dmarc.$domain)",
                    severity = if (mxRecords.isNotEmpty()) "MEDIUM" else "LOW",
                    endpoint = "_dmarc.$domain (DNS TXT)",
                    summary = "No DMARC record exists at _dmarc.$domain, leaving the domain vulnerable to phishing and direct domain spoofing.",
                    evidence = "_dmarc.$domain TXT: <missing>",
                    reproCommand = "dig +short _dmarc.$domain TXT",
                    remediation = "Publish a DMARC record at _dmarc.$domain with an enforcement policy ('v=DMARC1; p=quarantine; rua=mailto:dmarc@$domain')."
                )
            )
        } else if (dmarcRecord.contains("p=none", ignoreCase = true)) {
            addFinding(
                VulnerabilityFinding(
                    title = "DMARC Policy Set to Monitoring Only (p=none)",
                    severity = "LOW",
                    endpoint = "_dmarc.$domain (DNS TXT)",
                    summary = "DMARC is configured with 'p=none', meaning spoofed emails failing alignment are still delivered to recipients' inboxes.",
                    evidence = "Current DMARC Record: $dmarcRecord",
                    reproCommand = "dig +short _dmarc.$domain TXT",
                    remediation = "Upgrade the DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject' once legitimate mail sources are verified."
                )
            )
        }
    }

    // ==================== 3. TLS & SECURITY HEADERS ====================
    private fun auditTlsAndHeaders(targetUrl: String, domain: String) {
        try {
            val conn = (URL(targetUrl).openConnection() as HttpsURLConnection).apply {
                instanceFollowRedirects = true
                connectTimeout = 8000
                readTimeout = 8000
                setRequestProperty("User-Agent", "Mozilla/5.0 BountyScopeAudit/2.0")
            }

            val status = conn.responseCode
            val headers = conn.headerFields
            logLine("   ↳ Connected (HTTP $status). Analyzing security headers & TLS...")

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
                                summary = "The TLS certificate for $domain expires on ${x509.notAfter}.",
                                evidence = "Subject: ${x509.subjectDN}\nExpires: ${x509.notAfter}",
                                reproCommand = "openssl s_client -connect $domain:443 </dev/null 2>/dev/null | openssl x509 -noout -dates",
                                remediation = "Renew the TLS certificate and enable automated ACME renewal."
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

            val hsts = getHeader("Strict-Transport-Security")
            if (hsts == null) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing HTTP Strict Transport Security (HSTS)",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "The application does not send a Strict-Transport-Security header, allowing potential SSL-stripping on first visit.",
                        evidence = "HTTP $status response lacked 'Strict-Transport-Security'.",
                        reproCommand = "curl -I -s $targetUrl | grep -i strict-transport-security",
                        remediation = "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses."
                    )
                )
            }

            val xfo = getHeader("X-Frame-Options")
            val csp = getHeader("Content-Security-Policy")
            val hasFrameAncestors = csp?.contains("frame-ancestors", ignoreCase = true) == true
            if (xfo == null && !hasFrameAncestors) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing Anti-Clickjacking Protection (X-Frame-Options / CSP)",
                        severity = "MEDIUM",
                        endpoint = targetUrl,
                        summary = "Neither X-Frame-Options nor CSP frame-ancestors is configured, enabling attackers to embed sensitive pages inside an invisible iframe.",
                        evidence = "X-Frame-Options: <missing>\nContent-Security-Policy: ${csp ?: "<missing>"}",
                        reproCommand = "curl -I -s $targetUrl | grep -iE \"x-frame-options|content-security-policy\"",
                        remediation = "Set 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: SAMEORIGIN'."
                    )
                )
            }

            if (csp == null) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing Content-Security-Policy (CSP) Header",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "No Content-Security-Policy header is enforced, increasing the exploitability impact of any Cross-Site Scripting (XSS) vulnerability.",
                        evidence = "HTTP $status response contained no Content-Security-Policy header.",
                        reproCommand = "curl -I -s $targetUrl | grep -i content-security-policy",
                        remediation = "Implement a restrictive Content-Security-Policy with nonce-based script execution."
                    )
                )
            }

            val xcto = getHeader("X-Content-Type-Options")
            if (xcto == null || !xcto.equals("nosniff", ignoreCase = true)) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing X-Content-Type-Options: nosniff",
                        severity = "LOW",
                        endpoint = targetUrl,
                        summary = "Browsers may MIME-sniff responses away from the declared Content-Type.",
                        evidence = "X-Content-Type-Options: ${xcto ?: "<missing>"}",
                        reproCommand = "curl -I -s $targetUrl | grep -i x-content-type-options",
                        remediation = "Set 'X-Content-Type-Options: nosniff' across all HTTP responses."
                    )
                )
            }

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
                        remediation = "Strip version numbers from the Server banner and remove X-Powered-By headers."
                    )
                )
            }

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
    // ==================== 4. CORS POLICY CHECK ====================
    private fun auditCorsPolicy(targetUrl: String) {
        val evilOrigin = "https://evil-attacker.example"
        try {
            val conn = (URL(targetUrl).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 7000
                readTimeout = 7000
                setRequestProperty("Origin", evilOrigin)
                setRequestProperty("User-Agent", "BountyScopeAudit/2.0")
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
                        evidence = "Request Origin: $evilOrigin\nAccess-Control-Allow-Origin: $acao\nAccess-Control-Allow-Credentials: ${acac ?: "false"}",
                        reproCommand = "curl -I -s -H \"Origin: $evilOrigin\" $targetUrl | grep -i access-control",
                        remediation = "Validate the Origin header against a strict server-side allowlist of trusted domains."
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

    // ==================== 5. WELL-KNOWN & .GIT EXPOSURE ====================
    private fun auditWellKnownAndGit(targetUrl: String) {
        try {
            val secUrl = "$targetUrl/.well-known/security.txt"
            val conn = (URL(secUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 5000
                readTimeout = 5000
            }
            if (conn.responseCode == 200) {
                val body = readBodySnippet(conn, 1024)
                if (body.contains("Contact:", ignoreCase = true)) {
                    logLine("   ↳ Verified /.well-known/security.txt disclosure policy.")
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }

        try {
            val gitUrl = "$targetUrl/.git/HEAD"
            val conn = (URL(gitUrl).openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 5000
                readTimeout = 5000
            }
            if (conn.responseCode == 200) {
                val body = readBodySnippet(conn, 512).trim()
                if (body.startsWith("ref: refs/")) {
                    addFinding(
                        VulnerabilityFinding(
                            title = "Exposed .git Repository Metadata (/.git/HEAD)",
                            severity = "HIGH",
                            endpoint = gitUrl,
                            summary = "The web root publicly serves .git/HEAD, potentially allowing full source code and commit history reconstruction.",
                            evidence = "GET $gitUrl -> HTTP 200\nBody: $body",
                            reproCommand = "curl -s $gitUrl",
                            remediation = "Block public web server access to all dotfiles/directories (e.g., 'location ~ /\\. { deny all; }')."
                        )
                    )
                    logLine("   ↳ [!] HIGH: Exposed .git/HEAD detected!")
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
    }

    // ==================== 6. CUSTOM ENDPOINT WORDLIST PROBER ====================
    private fun probeCustomWordlist(targetUrl: String, paths: List<String>) {
        if (paths.isEmpty()) return

        // Step A: Capture Soft-404 baseline using a guaranteed random path
        var baselineStatus = 404
        var baselineLength = -1
        var baselineSignature = ""

        try {
            val randomSlug = "/bountyscope-404-check-${UUID.randomUUID().toString().take(8)}"
            val baseConn = (URL("$targetUrl$randomSlug").openConnection() as HttpURLConnection).apply {
                instanceFollowRedirects = false
                connectTimeout = 5000
                readTimeout = 5000
                setRequestProperty("User-Agent", "BountyScopeAudit/2.0")
            }
            baselineStatus = baseConn.responseCode
            val baseBody = readBodySnippet(baseConn, 2048)
            baselineLength = baseBody.length
            baselineSignature = baseBody.take(160)
            baseConn.disconnect()
        } catch (_: Exception) {
        }

        // Step B: Probe each endpoint in the user's wordlist
        for (path in paths) {
            val fullUrl = "$targetUrl$path"
            try {
                val conn = (URL(fullUrl).openConnection() as HttpURLConnection).apply {
                    instanceFollowRedirects = false
                    connectTimeout = 5000
                    readTimeout = 5000
                    setRequestProperty("User-Agent", "BountyScopeAudit/2.0")
                }

                val code = conn.responseCode
                val contentType = conn.contentType ?: "unknown"
                val snippet = readBodySnippet(conn, 2048)
                conn.disconnect()

                // Filter out Soft-404 / SPA catch-all responses
                val isSoft404 = (baselineStatus == 200 && code == 200) &&
                    (kotlin.math.abs(snippet.length - baselineLength) <= 50 ||
                        (baselineSignature.isNotEmpty() && snippet.startsWith(baselineSignature)))

                if (isSoft404 || code == 404 || code == 400 && !path.contains("graphql", ignoreCase = true)) {
                    continue
                }

                when {
                    // Exposed .env file
                    path.contains(".env", ignoreCase = true) && code == 200 &&
                        !contentType.contains("text/html", ignoreCase = true) &&
                        snippet.contains("=") -> {
                        logLine("   ↳ [!] HIGH: Exposed environment file at $path")
                        addFinding(
                            VulnerabilityFinding(
                                title = "Exposed Environment Configuration File ($path)",
                                severity = "HIGH",
                                endpoint = fullUrl,
                                summary = "Sensitive environment configuration file ($path) is publicly accessible over HTTP, potentially leaking API keys, database credentials, or secrets.",
                                evidence = "HTTP $code ($contentType)\nPreview:\n${snippet.take(220)}",
                                reproCommand = "curl -i -s $fullUrl",
                                remediation = "Remove $path from the public web root and block access to hidden files in web server rules."
                            )
                        )
                    }

                    // Exposed Swagger / OpenAPI docs
                    (path.contains("swagger", ignoreCase = true) || path.contains("openapi", ignoreCase = true)) &&
                        code == 200 && (snippet.contains("openapi", ignoreCase = true) || snippet.contains("swagger", ignoreCase = true)) -> {
                        logLine("   ↳ [!] MEDIUM: Public API schema at $path")
                        addFinding(
                            VulnerabilityFinding(
                                title = "Publicly Exposed OpenAPI / Swagger Specification ($path)",
                                severity = "MEDIUM",
                                endpoint = fullUrl,
                                summary = "Interactive API schema documentation is publicly accessible at $path, exposing internal routes, parameters, and data models.",
                                evidence = "HTTP $code ($contentType)\nPreview:\n${snippet.take(220)}",
                                reproCommand = "curl -s $fullUrl | head -n 25",
                                remediation = "Disable public Swagger/OpenAPI endpoints in production or restrict them to authenticated internal users."
                            )
                        )
                    }

                    // GraphQL endpoint
                    path.contains("graphql", ignoreCase = true) && (code == 200 || code == 400) &&
                        (snippet.contains("graphql", ignoreCase = true) || snippet.contains("query", ignoreCase = true)) -> {
                        logLine("   ↳ [+] GraphQL endpoint active at $path (HTTP $code)")
                        addFinding(
                            VulnerabilityFinding(
                                title = "Active GraphQL API Endpoint Discovered ($path)",
                                severity = "LOW",
                                endpoint = fullUrl,
                                summary = "A GraphQL endpoint responded at $path (HTTP $code). Verify whether GraphQL Introspection is enabled in production.",
                                evidence = "HTTP $code ($contentType)\nResponse: ${snippet.take(180)}",
                                reproCommand = "curl -s -X POST -H \"Content-Type: application/json\" -d '{\"query\":\"{__schema{types{name}}}\"}' $fullUrl",
                                remediation = "Disable GraphQL schema introspection in production environments and enforce query depth/rate limits."
                            )
                        )
                    }

                    // WordPress user enumeration
                    path.contains("wp-json/wp/v2/users", ignoreCase = true) && code == 200 &&
                        snippet.contains("\"slug\"", ignoreCase = true) -> {
                        logLine("   ↳ [!] LOW: WordPress user list exposed at $path")
                        addFinding(
                            VulnerabilityFinding(
                                title = "WordPress REST API User Enumeration ($path)",
                                severity = "LOW",
                                endpoint = fullUrl,
                                summary = "The WordPress REST API publicly enumerates registered usernames and author slugs at $path.",
                                evidence = "HTTP $code ($contentType)\nPreview: ${snippet.take(200)}",
                                reproCommand = "curl -s $fullUrl",
                                remediation = "Restrict unauthenticated access to /wp-json/wp/v2/users via security plugin or REST API filter."
                            )
                        )
                    }

                    // Health / Actuator endpoints
                    (path.contains("health", ignoreCase = true) || path.contains("actuator", ignoreCase = true)) &&
                        code == 200 && !contentType.contains("text/html", ignoreCase = true) -> {
                        logLine("   ↳ [+] Diagnostics endpoint exposed at $path (HTTP 200)")
                        addFinding(
                            VulnerabilityFinding(
                                title = "Publicly Accessible Health / Diagnostics Endpoint ($path)",
                                severity = "LOW",
                                endpoint = fullUrl,
                                summary = "Service health or actuator telemetry is publicly exposed at $path, leaking operational status or dependency details.",
                                evidence = "HTTP $code ($contentType)\nResponse: ${snippet.take(200)}",
                                reproCommand = "curl -i -s $fullUrl",
                                remediation = "Restrict actuator and internal health endpoints to internal network interfaces or require authentication."
                            )
                        )
                    }

                    // Admin / Server-Status panels (200, 401, 403)
                    code in listOf(200, 401, 403) -> {
                        logLine("   ↳ [+] Endpoint responded: $path (HTTP $code)")
                        addFinding(
                            VulnerabilityFinding(
                                title = "Sensitive Path Discovered: $path (HTTP $code)",
                                severity = "INFO",
                                endpoint = fullUrl,
                                summary = "Endpoint $path returned HTTP $code ($contentType) during automated wordlist probing.",
                                evidence = "GET $fullUrl -> HTTP $code\nContent-Type: $contentType",
                                reproCommand = "curl -i -s $fullUrl | head -n 20",
                                remediation = "Verify that administrative or internal interfaces enforce strong authentication, MFA, and IP access restrictions."
                            )
                        )
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    private fun readBodySnippet(conn: HttpURLConnection, maxChars: Int): String {
        return try {
            val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
            if (stream == null) return ""
            BufferedReader(InputStreamReader(stream)).use { reader ->
                val buf = CharArray(maxChars)
                val read = reader.read(buf, 0, maxChars)
                if (read > 0) String(buf, 0, read) else ""
            }
        } catch (_: Exception) {
            ""
        }
    }
    // ==================== UI RENDERING, SQLITE HISTORY & MARKDOWN REPORT ====================

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
        scanButton.text = "▶ RUN FULL AUTOMATED SCAN & SAVE REPORT"
        progressBar.visibility = ProgressBar.GONE

        logLine("[DONE] Scan complete & saved offline. Findings logged: ${findings.size}")

        if (findings.isNotEmpty()) {
            generateReportBtn.isEnabled = true
            generateReportBtn.alpha = 1.0f
        } else {
            val cleanTxt = TextView(this).apply {
                text = "No misconfigurations or exposed endpoints detected on $lastScannedTarget."
                textSize = 13f
                setTextColor(neonGreen)
                setPadding(12, 12, 12, 12)
            }
            findingsContainer.addView(cleanTxt)
        }
    }

    private fun refreshHistoryBadge() {
        val count = scanDatabase.getReportCount()
        historyBadgeBtn.text = "🗄️ HISTORY ($count)"
    }

    private fun showSavedReportsDialog() {
        val savedList = scanDatabase.getAllReports()
        if (savedList.isEmpty()) {
            toast("No offline scan reports saved yet.")
            return
        }

        val scroll = ScrollView(this).apply {
            setPadding(28, 20, 28, 20)
        }
        val listLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        savedList.forEach { report ->
            val itemCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(20, 16, 20, 16)
                background = roundedBox(cardBg, borderColor, 2, 14f)
            }

            val domainTxt = TextView(this).apply {
                text = "${report.targetDomain}  (${report.scannedAt})"
                textSize = 14f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.WHITE)
            }

            val progTxt = TextView(this).apply {
                text = "${report.programName}\nTotal: ${report.findingsCount}  |  High: ${report.highCount} · Med: ${report.medCount} · Low: ${report.lowCount}"
                textSize = 12f
                setTextColor(Color.LTGRAY)
                setPadding(0, 6, 0, 10)
            }

            val actionRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }

            val openBtn = Button(this).apply {
                text = "OPEN REPORT"
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.BLACK)
                background = roundedBox(cyanAccent, cyanAccent, 0, 10f)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { setMargins(0, 0, 8, 0) }
                setOnClickListener {
                    showReportDialog(
                        dialogTitle = "Saved Report: ${report.targetDomain}",
                        markdownContent = report.markdownReport,
                        subjectTarget = report.targetDomain
                    )
                }
            }

            val delBtn = Button(this).apply {
                text = "DELETE"
                textSize = 11f
                setTextColor(Color.WHITE)
                background = roundedBox(highColor, highColor, 0, 10f)
                setOnClickListener {
                    scanDatabase.deleteReport(report.id)
                    refreshHistoryBadge()
                    toast("Deleted report for ${report.targetDomain}")
                    showSavedReportsDialog()
                }
            }

            actionRow.addView(openBtn)
            actionRow.addView(delBtn)

            itemCard.addView(domainTxt)
            itemCard.addView(progTxt)
            itemCard.addView(actionRow)

            val margin = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 12) }

            listLayout.addView(itemCard, margin)
        }

        scroll.addView(listLayout)

        AlertDialog.Builder(this)
            .setTitle("OFFLINE SAVED SCAN REPORTS (${savedList.size})")
            .setView(scroll)
            .setNeutralButton("CLEAR ALL") { _, _ ->
                scanDatabase.clearAllReports()
                refreshHistoryBadge()
                toast("All saved reports cleared.")
            }
            .setPositiveButton("CLOSE", null)
            .show()
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
            sb.appendLine("## ${idx + 1}. [${f.severity}] ${f.title}")
            sb.appendLine("**Affected Endpoint:** `${f.endpoint}`\n")
            sb.appendLine("### Summary")
            sb.appendLine("${f.summary}\n")
            sb.appendLine("### Steps to Reproduce")
            sb.appendLine("1. Open a terminal or HTTP proxy.")
            sb.appendLine("2. Run the verification command below:")
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
        showReportDialog(finding.title, md, lastScannedTarget)
    }

    private fun showFullReportModal() {
        val md = buildMarkdownReport(findings.toList())
        showReportDialog("Full Bounty Report ($lastScannedTarget)", md, lastScannedTarget)
    }

    private fun showReportDialog(
        dialogTitle: String,
        markdownContent: String,
        subjectTarget: String
    ) {
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
                    putExtra(Intent.EXTRA_SUBJECT, "Bug Bounty Report - $subjectTarget")
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
        scanDatabase.close()
        super.onDestroy()
    }
}
    
