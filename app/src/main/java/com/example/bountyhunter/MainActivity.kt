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
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
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
import java.util.regex.Pattern
import javax.net.ssl.HttpsURLConnection

data class VulnerabilityFinding(
    val title: String,
    val category: String, // XSS, SQLi, RCE, IDOR, INJECTION, WEB3, MISCONFIG, RECON
    val severity: String, // CRITICAL, HIGH, MEDIUM, LOW, INFO
    val cvssScore: Double,
    val cvssVector: String,
    val endpoint: String,
    val description: String,
    val securityPrivacyRisk: String,
    val mobileImpact: String,
    val optionalSetupSteps: String,
    val reproSteps: String,
    val evidence: String,
    val solutionFix: String
)

class MainActivity : Activity() {

    private lateinit var scanDatabase: ScanDatabase
    private val executor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private lateinit var historyBadgeBtn: Button
    private lateinit var programInput: EditText
    private lateinit var targetInput: EditText
    private lateinit var authHeaderInput: EditText
    private lateinit var cookieHeaderInput: EditText
    private lateinit var wordlistInput: EditText
    private lateinit var depthButton: Button
    private lateinit var templateButton: Button
    private lateinit var scopeCheckBox: CheckBox
    private lateinit var scanButton: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var liveLogText: TextView
    private lateinit var subdomainSection: LinearLayout
    private lateinit var subdomainChipsRow: LinearLayout
    private lateinit var critCountTxt: TextView
    private lateinit var highCountTxt: TextView
    private lateinit var medCountTxt: TextView
    private lateinit var lowCountTxt: TextView
    private lateinit var findingsContainer: LinearLayout
    private lateinit var generateReportBtn: Button

    // Interactive Attack Module Toggles
    private var enableXss = true
    private var enableSqli = true
    private var enableRce = true
    private var enableIdor = true
    private var enableWeb3 = true

    private val findings = Collections.synchronizedList(mutableListOf<VulnerabilityFinding>())
    private val discoveredSubdomains = Collections.synchronizedList(mutableListOf<String>())
    private val detectedTechStack = Collections.synchronizedSet(linkedSetOf<String>())

    private var lastScannedTarget = ""
    private var lastProgramName = "Meta"
    private var activeAuthHeader = ""
    private var activeCookieHeader = ""
    private var recursionDepth = 2
    private var reportTemplateMode = "META_WHITEHAT" // "META_WHITEHAT" or "HACKERONE"
    private var isScanning = false

    // Red-Team SOC Cybersecurity Palette
    private val bgDark = Color.parseColor("#05080D")
    private val panelBg = Color.parseColor("#0D131F")
    private val inputBg = Color.parseColor("#131C2E")
    private val borderColor = Color.parseColor("#1E2D4A")
    private val matrixGreen = Color.parseColor("#00FF9C")
    private val cyberCyan = Color.parseColor("#00E5FF")
    private val neonPurple = Color.parseColor("#A855F7")
    private val critColor = Color.parseColor("#FF2A55")
    private val highColor = Color.parseColor("#FF7A00")
    private val medColor = Color.parseColor("#FACC15")
    private val lowColor = Color.parseColor("#38BDF8")
    private val infoColor = Color.parseColor("#94A3B8")

    private val defaultWordlist =
        "/admin, /api/v1/users/1, /swagger.json, /graphql, /.env, /.git/config, /actuator/env, /rpc, /artifacts/contracts"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        scanDatabase = ScanDatabase(this)
        buildCyberSocUI()
        refreshHistoryBadge()
    }

    private fun buildCyberSocUI() {
        val scroll = ScrollView(this).apply {
            setBackgroundColor(bgDark)
            isFillViewport = true
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(30, 34, 30, 48)
        }

        // Top SOC HUD Bar
        val hudBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(20, 14, 20, 14)
            background = roundedBox(panelBg, matrixGreen, 1, 14f)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 16) }
        }

        val hudStatusCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val hudPill = TextView(this).apply {
            text = "● RED-TEAM RECON & VULN ENGINE v4.0"
            textSize = 10f
            typeface = Typeface.MONOSPACE
            setTextColor(matrixGreen)
        }

        val appTitle = TextView(this).apply {
            text = "BountyScope Studio"
            textSize = 24f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(0, 2, 0, 0)
        }

        hudStatusCol.addView(hudPill)
        hudStatusCol.addView(appTitle)

        historyBadgeBtn = Button(this).apply {
            text = "🗄️ VAULT (0)"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(matrixGreen)
            setPadding(18, 12, 18, 12)
            background = roundedBox(inputBg, matrixGreen, 1, 12f)
            setOnClickListener { showSavedReportsDialog() }
        }

        hudBar.addView(hudStatusCol)
        hudBar.addView(historyBadgeBtn)
        root.addView(hudBar)

        // Severity Telemetry Counter Bar
        val metricsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 16) }
        }

        critCountTxt = createMetricBox("CRITICAL", "0", critColor)
        highCountTxt = createMetricBox("HIGH", "0", highColor)
        medCountTxt = createMetricBox("MEDIUM", "0", medColor)
        lowCountTxt = createMetricBox("LOW", "0", lowColor)

        val metricParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            .apply { setMargins(5, 0, 5, 0) }

        metricsRow.addView(critCountTxt, metricParams)
        metricsRow.addView(highCountTxt, metricParams)
        metricsRow.addView(medCountTxt, metricParams)
        metricsRow.addView(lowCountTxt, metricParams)
        root.addView(metricsRow)

        // Target & Attack Module Configuration Card
        val configCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(22, 22, 22, 22)
            background = roundedBox(panelBg, borderColor, 2, 18f)
        }

        val programLabel = TextView(this).apply {
            text = "TARGET ORGANIZATION / PROGRAM (E.G., META)"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(cyberCyan)
        }

        programInput = EditText(this).apply {
            setText("Meta")
            hint = "e.g., Meta Whitehat / HackerOne Program"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(20, 14, 20, 14)
            background = roundedBox(inputBg, borderColor, 1, 12f)
        }

        val targetLabel = TextView(this).apply {
            text = "IN-SCOPE TARGET DOMAIN OR SUBDOMAIN"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(cyberCyan)
            setPadding(0, 12, 0, 0)
        }

        targetInput = EditText(this).apply {
            hint = "e.g., staging.example.com (without https://)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(20, 14, 20, 14)
            background = roundedBox(inputBg, borderColor, 1, 12f)
        }

        // Active Vulnerability Module Chips (XSS, SQLi, RCE, IDOR, WEB3)
        val modulesLabel = TextView(this).apply {
            text = "ACTIVE EXPLOIT & INJECTION MODULES (TAP TO TOGGLE)"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(matrixGreen)
            setPadding(0, 14, 0, 8)
        }

        val moduleScroll = HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
        }
        val moduleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }

        moduleRow.addView(createModuleToggleChip("XSS", enableXss) { enableXss = it })
        moduleRow.addView(createModuleToggleChip("SQLi", enableSqli) { enableSqli = it })
        moduleRow.addView(createModuleToggleChip("RCE / SSTI", enableRce) { enableRce = it })
        moduleRow.addView(createModuleToggleChip("IDOR", enableIdor) { enableIdor = it })
        moduleRow.addView(createModuleToggleChip("WEB3 / RPC", enableWeb3) { enableWeb3 = it })
        moduleScroll.addView(moduleRow)

        // Authenticated Session Headers
        val authLabel = TextView(this).apply {
            text = "SESSION AUTH HEADERS (REQUIRED FOR DEEP IDOR & AUTH ENDPOINTS)"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(neonPurple)
            setPadding(0, 14, 0, 0)
        }

        authHeaderInput = EditText(this).apply {
            hint = "Authorization: Bearer <token>"
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(20, 13, 20, 13)
            background = roundedBox(inputBg, borderColor, 1, 12f)
        }

        cookieHeaderInput = EditText(this).apply {
            hint = "Cookie: session_id=...; user_id=..."
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setSingleLine(true)
            setPadding(20, 13, 20, 13)
            background = roundedBox(inputBg, borderColor, 1, 12f)
        }

        // Crawl Depth & Report Schema Mode
        val engineControlsRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 12, 0, 6) }
        }

        depthButton = Button(this).apply {
            text = "DEPTH: $recursionDepth"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = roundedBox(inputBg, cyberCyan, 1, 12f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(0, 0, 8, 0) }
            setOnClickListener {
                recursionDepth = (recursionDepth % 3) + 1
                text = "DEPTH: $recursionDepth"
            }
        }

        templateButton = Button(this).apply {
            text = "REPORT: $reportTemplateMode"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            background = roundedBox(inputBg, neonPurple, 1, 12f)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { setMargins(8, 0, 0, 0) }
            setOnClickListener {
                reportTemplateMode =
                    if (reportTemplateMode == "META_WHITEHAT") "HACKERONE" else "META_WHITEHAT"
                text = "REPORT: $reportTemplateMode"
            }
        }

        engineControlsRow.addView(depthButton)
        engineControlsRow.addView(templateButton)

        // Wordlist
        val wordlistLabel = TextView(this).apply {
            text = "TARGET WORDLIST (+ AUTO TECH-STACK & WEB3 ROUTES)"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(cyberCyan)
            setPadding(0, 10, 0, 0)
        }

        wordlistInput = EditText(this).apply {
            setText(defaultWordlist)
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.WHITE)
            minLines = 2
            maxLines = 3
            setPadding(20, 13, 20, 13)
            background = roundedBox(inputBg, borderColor, 1, 12f)
        }

        scopeCheckBox = CheckBox(this).apply {
            text = "I confirm this asset is authorized in scope under bug bounty rules."
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(8, 12, 8, 10)
        }

        scanButton = Button(this).apply {
            text = "⚡ LAUNCH AUTOMATED VULNERABILITY SCAN"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.BLACK)
            setPadding(20, 22, 20, 22)
            background = roundedBox(matrixGreen, matrixGreen, 0, 14f)
            setOnClickListener { startAutomatedScan(targetInput.text.toString()) }
        }

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = true
            visibility = ProgressBar.GONE
            setPadding(0, 12, 0, 0)
        }

        val fieldParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 6, 0, 6) }

        configCard.addView(programLabel)
        configCard.addView(programInput, fieldParams)
        configCard.addView(targetLabel)
        configCard.addView(targetInput, fieldParams)
        configCard.addView(modulesLabel)
        configCard.addView(moduleScroll)
        configCard.addView(authLabel)
        configCard.addView(authHeaderInput, fieldParams)
        configCard.addView(cookieHeaderInput, fieldParams)
        configCard.addView(engineControlsRow)
        configCard.addView(wordlistLabel)
        configCard.addView(wordlistInput, fieldParams)
        configCard.addView(scopeCheckBox)
        configCard.addView(scanButton, fieldParams)
        configCard.addView(progressBar)

        val cardSpacing = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 0, 0, 16) }
        root.addView(configCard, cardSpacing)

        // Subdomain Quick-Pivot Strip
        subdomainSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(18, 14, 18, 14)
            background = roundedBox(panelBg, cyberCyan, 1, 14f)
            visibility = LinearLayout.GONE
        }
        val subHeader = TextView(this).apply {
            text = "DISCOVERED SUBDOMAINS (TAP TO PIVOT DEEP SCAN)"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(cyberCyan)
            setPadding(0, 0, 0, 8)
        }
        val subScroll = HorizontalScrollView(this).apply { isHorizontalScrollBarEnabled = false }
        subdomainChipsRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        subScroll.addView(subdomainChipsRow)
        subdomainSection.addView(subHeader)
        subdomainSection.addView(subScroll)
        root.addView(subdomainSection, cardSpacing)

        // Live Attack Console
        val consoleCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 16, 20, 16)
            background = roundedBox(Color.parseColor("#030508"), matrixGreen, 1, 14f)
        }
        val consoleHeader = TextView(this).apply {
            text = "root@bountyscope:~# LIVE TELEMETRY STREAM"
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(matrixGreen)
            setPadding(0, 0, 0, 8)
        }
        liveLogText = TextView(this).apply {
            text = "[IDLE] Ready to probe XSS, SQLi, RCE/SSTI, IDOR, Web3, CORS & Takeovers..."
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#CBD5E1"))
        }
        consoleCard.addView(consoleHeader)
        consoleCard.addView(liveLogText)
        root.addView(consoleCard, cardSpacing)

        // Full Report Export CTA
        generateReportBtn = Button(this).apply {
            text = "📋 GENERATE FULL BUG BOUNTY SUBMISSION REPORT"
            textSize = 14f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(20, 22, 20, 22)
            background = roundedBox(neonPurple, neonPurple, 0, 14f)
            isEnabled = false
            alpha = 0.45f
            setOnClickListener { showFullReportModal() }
        }
        root.addView(generateReportBtn, cardSpacing)

        val findingsHeader = TextView(this).apply {
            text = "TRIAGED VULNERABILITY FINDINGS"
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.WHITE)
            setPadding(4, 2, 4, 10)
        }
        root.addView(findingsHeader)

        findingsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        root.addView(findingsContainer)

        scroll.addView(root)
        setContentView(scroll)
    }

    private fun createMetricBox(label: String, count: String, accent: Int): TextView {
        return TextView(this).apply {
            text = "$count\n$label"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(accent)
            gravity = Gravity.CENTER
            setPadding(8, 12, 8, 12)
            background = roundedBox(panelBg, accent, 1, 12f)
        }
    }

    private fun createModuleToggleChip(
        name: String,
        initialState: Boolean,
        onToggle: (Boolean) -> Unit
    ): Button {
        var active = initialState
        return Button(this).apply {
            text = if (active) "✓ $name" else "✕ $name"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(if (active) Color.BLACK else Color.GRAY)
            setPadding(18, 8, 18, 8)
            background = roundedBox(
                if (active) matrixGreen else inputBg,
                if (active) matrixGreen else borderColor,
                1,
                24f
            )
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 10, 0) }

            setOnClickListener {
                active = !active
                onToggle(active)
                text = if (active) "✓ $name" else "✕ $name"
                setTextColor(if (active) Color.BLACK else Color.GRAY)
                background = roundedBox(
                    if (active) matrixGreen else inputBg,
                    if (active) matrixGreen else borderColor,
                    1,
                    24f
                )
            }
        }
    }

    // ==================== MAIN SCAN ORCHESTRATOR ====================
    private fun startAutomatedScan(targetInputRaw: String) {
        if (isScanning) return

        val rawTarget = targetInputRaw.trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .trimEnd('/')

        if (rawTarget.isBlank() || !rawTarget.contains(".")) {
            toast("Enter a valid in-scope domain (e.g., example.com)")
            return
        }

        if (!scopeCheckBox.isChecked) {
            toast("Confirm target scope authorization first.")
            return
        }

        targetInput.setText(rawTarget)
        activeAuthHeader = authHeaderInput.text.toString().trim()
        activeCookieHeader = cookieHeaderInput.text.toString().trim()

        val userPaths = wordlistInput.text.toString()
            .split(",", "\n")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { if (it.startsWith("/")) it else "/$it" }
            .distinct()

        isScanning = true
        findings.clear()
        discoveredSubdomains.clear()
        detectedTechStack.clear()
        findingsContainer.removeAllViews()
        subdomainChipsRow.removeAllViews()
        subdomainSection.visibility = LinearLayout.GONE

        lastScannedTarget = rawTarget
        lastProgramName = programInput.text.toString().trim().ifEmpty { "Meta" }

        scanButton.isEnabled = false
        scanButton.text = "⏳ EXECUTING ACTIVE SECURITY PROBES..."
        progressBar.visibility = ProgressBar.VISIBLE
        generateReportBtn.isEnabled = false
        generateReportBtn.alpha = 0.45f
        liveLogText.text = ""
        updateSeverityCounters()

        executor.execute {
            try {
                logLine("[1/9] Enumerating subdomains & checking Subdomain Takeover CNAMEs...")
                val subs = enumerateSubdomains(rawTarget)
                auditSubdomainTakeovers(rawTarget, subs)

                val targetUrl = "https://$rawTarget"
                logLine("[2/9] Fingerprinting stack, TLS, CORS & security headers...")
                val homepageHtml = inspectStackHeadersAndCors(targetUrl, rawTarget)

                logLine("[3/9] Scanning JavaScript bundles for API keys, Web3 keys & sourcemaps...")
                scanJsBundlesAndWeb3Secrets(targetUrl, homepageHtml)

                if (enableXss) {
                    logLine("[4/9] Probing XSS & Server-Side Template Injection (SSTI) vectors...")
                    probeXssAndSsti(targetUrl)
                }

                if (enableSqli) {
                    logLine("[5/9] Probing SQL Injection (SQLi) error & boolean differential vectors...")
                    probeSqlInjection(targetUrl)
                }

                if (enableRce) {
                    logLine("[6/9] Probing RCE / OS Command Injection parameters...")
                    probeCommandInjectionRce(targetUrl)
                }

                if (enableIdor) {
                    logLine("[7/9] Testing IDOR (Insecure Direct Object Reference) object enumeration...")
                    probeIdorEndpoints(targetUrl)
                }

                if (enableWeb3) {
                    logLine("[8/9] Auditing Web3 JSON-RPC nodes & smart contract artifacts...")
                    probeWeb3Endpoints(targetUrl)
                }

                val dynamicWordlist = buildStackAwareWordlist(userPaths)
                logLine("[9/9] Recursive directory probing (${dynamicWordlist.size} paths, depth=$recursionDepth)...")
                recursiveProbeWordlist(targetUrl, dynamicWordlist, maxDepth = recursionDepth)

                val sortedFindings = findings.sortedByDescending { it.cvssScore }
                findings.clear()
                findings.addAll(sortedFindings)

                val fullMarkdown = buildMarkdownReport(sortedFindings)
                scanDatabase.saveReport(
                    programName = lastProgramName,
                    targetDomain = lastScannedTarget,
                    findings = sortedFindings,
                    markdownReport = fullMarkdown
                )

                mainHandler.post {
                    findingsContainer.removeAllViews()
                    sortedFindings.forEach { renderFindingCard(it) }
                    refreshHistoryBadge()
                    finishScanUI()
                }
            } catch (e: Exception) {
                logLine("[ERROR] Scan aborted: ${e.message}")
                mainHandler.post {
                    isScanning = false
                    scanButton.isEnabled = true
                    scanButton.text = "⚡ LAUNCH AUTOMATED VULNERABILITY SCAN"
                    progressBar.visibility = ProgressBar.GONE
                }
            }
        }
    }
    // ==================== HTTP CONNECTION HELPERS ====================
    private fun openConfiguredConnection(
        urlStr: String,
        followRedirects: Boolean = false,
        method: String = "GET"
    ): HttpURLConnection {
        return (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            instanceFollowRedirects = followRedirects
            connectTimeout = 7000
            readTimeout = 7000
            setRequestProperty("User-Agent", "Mozilla/5.0 BountyScopeStudio/4.0")
            if (activeAuthHeader.isNotEmpty()) {
                setRequestProperty("Authorization", activeAuthHeader)
            }
            if (activeCookieHeader.isNotEmpty()) {
                setRequestProperty("Cookie", activeCookieHeader)
            }
        }
    }

    private fun buildCurlCommand(
        url: String,
        method: String = "GET",
        extraHeader: String? = null,
        postJson: String? = null
    ): String {
        val sb = StringBuilder("curl -i -s -X $method")
        if (extraHeader != null) sb.append(" -H \"$extraHeader\"")
        if (activeAuthHeader.isNotEmpty()) sb.append(" -H \"Authorization: <YOUR_BEARER_TOKEN>\"")
        if (activeCookieHeader.isNotEmpty()) sb.append(" -H \"Cookie: <YOUR_SESSION_COOKIE>\"")
        if (postJson != null) sb.append(" -d '$postJson'")
        sb.append(" \"$url\"")
        return sb.toString()
    }

    // ==================== 1. SUBDOMAIN ENUM & TAKEOVER ====================
    private fun enumerateSubdomains(domain: String): List<String> {
        val rootDomain = extractApexDomain(domain)
        val uniqueHosts = sortedSetOf<String>()
        try {
            val encoded = URLEncoder.encode("%.$rootDomain", "UTF-8")
            val conn = (URL("https://crt.sh/?q=$encoded&output=json").openConnection() as HttpURLConnection).apply {
                connectTimeout = 9000
                readTimeout = 9000
                setRequestProperty("User-Agent", "BountyScopeStudio/4.0")
            }
            if (conn.responseCode == 200) {
                val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                val arr = JSONArray(body)
                for (i in 0 until minOf(arr.length(), 400)) {
                    val nv = arr.getJSONObject(i).optString("name_value", "")
                    nv.split("\n").forEach { line ->
                        val clean = line.trim().lowercase(Locale.US).removePrefix("*.")
                        if (clean.endsWith(rootDomain) && clean != rootDomain && !clean.contains("*")) {
                            uniqueHosts.add(clean)
                        }
                    }
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }

        val list = uniqueHosts.take(30)
        discoveredSubdomains.addAll(list)
        logLine("   ↳ Discovered ${uniqueHosts.size} subdomains under *.$rootDomain.")

        if (list.isNotEmpty()) {
            mainHandler.post {
                subdomainSection.visibility = LinearLayout.VISIBLE
                subdomainChipsRow.removeAllViews()
                list.forEach { host ->
                    val chip = Button(this).apply {
                        text = "⚡ $host"
                        textSize = 11f
                        setTextColor(Color.WHITE)
                        setPadding(18, 8, 18, 8)
                        background = roundedBox(inputBg, cyberCyan, 1, 24f)
                        setOnClickListener { startAutomatedScan(host) }
                    }
                    val p = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT
                    ).apply { setMargins(0, 0, 10, 0) }
                    subdomainChipsRow.addView(chip, p)
                }
            }
        }
        return list
    }

    private fun auditSubdomainTakeovers(primaryTarget: String, subdomains: List<String>) {
        val fingerprints = mapOf(
            "github.io" to "There isn't a GitHub Pages site here",
            "herokuapp.com" to "No such app",
            "s3.amazonaws.com" to "NoSuchBucket",
            "vercel.app" to "DEPLOYMENT_NOT_FOUND",
            "netlify.app" to "Not Found - Request ID",
            "azurewebsites.net" to "404 Web Site not found"
        )
        val hosts = (listOf(primaryTarget) + subdomains.take(12)).distinct()
        for (host in hosts) {
            val cnames = queryGoogleDns(host, "CNAME")
            if (cnames.isEmpty()) continue
            val cname = cnames.first().lowercase(Locale.US).trimEnd('.')
            val match = fingerprints.entries.firstOrNull { cname.contains(it.key) } ?: continue

            try {
                val conn = openConfiguredConnection("http://$host", followRedirects = true)
                val code = conn.responseCode
                val body = readBodySnippet(conn, 2048)
                conn.disconnect()

                if (body.contains(match.value, ignoreCase = true)) {
                    logLine("   ↳ [!] HIGH: Subdomain Takeover detected on $host -> $cname")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Subdomain Takeover via Unclaimed Cloud CNAME on $host",
                            category = "MISCONFIG",
                            severity = "HIGH",
                            cvssScore = 8.2,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
                            endpoint = host,
                            description = "The subdomain '$host' resolves via a DNS CNAME record to '$cname', which is no longer provisioned on ${match.key} and serves the unclaimed fingerprint '${match.value}'.",
                            securityPrivacyRisk = "An attacker can register '$cname' on ${match.key} to host arbitrary malicious JavaScript under a trusted $lastProgramName subdomain, enabling session cookie theft, OAuth redirect hijacking, and credential phishing against users.",
                            mobileImpact = "Mobile apps (Android/iOS) trusting *.$lastScannedTarget in WebViews, deep links, or certificate/domain allowlists will load attacker-controlled content.",
                            optionalSetupSteps = "1. Ensure 'dig' and 'curl' are installed.\n2. Confirm DNS resolution for '$host'.",
                            reproSteps = "1. Query the CNAME record for '$host':\n   dig +short $host CNAME\n2. Send an HTTP GET request to 'http://$host' and observe the unclaimed provider response:\n   ${buildCurlCommand("http://$host")}",
                            evidence = "CNAME: $host -> $cname\nHTTP $code Response Fingerprint: \"${match.value}\"",
                            solutionFix = "Remove the dangling DNS CNAME record pointing '$host' to '$cname' from your DNS zone, or immediately re-claim the resource on ${match.key}."
                        )
                    )
                }
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 2. STACK, HEADERS & CORS ====================
    private fun inspectStackHeadersAndCors(targetUrl: String, domain: String): String {
        var html = ""
        try {
            val conn = openConfiguredConnection(targetUrl, followRedirects = true)
            val headers = conn.headerFields
            html = readBodySnippet(conn, 32768)

            fun hdr(name: String): String? =
                headers.entries.firstOrNull { it.key != null && it.key.equals(name, true) }?.value?.joinToString("; ")

            val poweredBy = hdr("X-Powered-By") ?: ""
            val cookies = headers.entries.firstOrNull { it.key != null && it.key.equals("Set-Cookie", true) }?.value ?: emptyList()
            val cookieJoin = cookies.joinToString(" ")

            if (html.contains("wp-content", true)) detectedTechStack.add("WordPress")
            if (cookieJoin.contains("laravel_session", true)) detectedTechStack.add("Laravel")
            if (poweredBy.contains("Express", true) || html.contains("__NEXT_DATA__", true)) detectedTechStack.add("Node.js")
            if (html.contains("Whitelabel Error Page", true) || cookieJoin.contains("JSESSIONID", true)) detectedTechStack.add("Spring Boot")

            val xfo = hdr("X-Frame-Options")
            val csp = hdr("Content-Security-Policy")
            if (xfo == null && (csp == null || !csp.contains("frame-ancestors", true))) {
                addFinding(
                    VulnerabilityFinding(
                        title = "Missing Anti-Clickjacking Headers (X-Frame-Options & CSP frame-ancestors)",
                        category = "MISCONFIG",
                        severity = "MEDIUM",
                        cvssScore = 4.3,
                        cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                        endpoint = targetUrl,
                        description = "HTTP responses from '$targetUrl' omit both 'X-Frame-Options' and the Content-Security-Policy 'frame-ancestors' directive, permitting third-party sites to frame the application.",
                        securityPrivacyRisk = "Attackers can embed authenticated $lastProgramName pages inside an invisible iframe and overlay deceptive UI elements to trick users into authorizing unintended actions.",
                        mobileImpact = "Mobile browsers and embedded WebViews can render the target inside third-party framing contexts without frame-busting enforcement.",
                        optionalSetupSteps = "1. Log into an active session on '$targetUrl' in a desktop or mobile browser.",
                        reproSteps = "1. Inspect the HTTP response headers for '$targetUrl':\n   ${buildCurlCommand(targetUrl)}\n2. Verify the absence of 'X-Frame-Options' and 'Content-Security-Policy: frame-ancestors'.",
                        evidence = "X-Frame-Options: <missing>\nContent-Security-Policy: ${csp ?: "<missing>"}",
                        solutionFix = "Configure the web server or CDN edge to return 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: SAMEORIGIN' on all HTML responses."
                    )
                )
            }
            conn.disconnect()
        } catch (_: Exception) {
        }

        // CORS Origin Reflection Check
        val evilOrigin = "https://attacker-origin.example"
        try {
            val corsConn = openConfiguredConnection(targetUrl, followRedirects = false).apply {
                setRequestProperty("Origin", evilOrigin)
            }
            val acao = corsConn.getHeaderField("Access-Control-Allow-Origin")
            val acac = corsConn.getHeaderField("Access-Control-Allow-Credentials")
            if (acao != null && acao.equals(evilOrigin, true)) {
                val withCreds = acac.equals("true", true)
                logLine("   ↳ [!] ${if (withCreds) "HIGH" else "MEDIUM"}: CORS Arbitrary Origin Reflection!")
                addFinding(
                    VulnerabilityFinding(
                        title = "Cross-Origin Resource Sharing (CORS) Arbitrary Origin Reflection",
                        category = "MISCONFIG",
                        severity = if (withCreds) "HIGH" else "MEDIUM",
                        cvssScore = if (withCreds) 8.1 else 5.3,
                        cvssVector = if (withCreds)
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
                        else
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        endpoint = targetUrl,
                        description = "The server dynamically reflects any arbitrary 'Origin' header in 'Access-Control-Allow-Origin'${if (withCreds) " while simultaneously returning 'Access-Control-Allow-Credentials: true'" else ""}.",
                        securityPrivacyRisk = "Any malicious website visited by an authenticated $lastProgramName user can issue cross-origin credentialed requests and exfiltrate private user data, tokens, or account settings.",
                        mobileImpact = "Hybrid mobile apps using WKWebView or Android WebView with local file:// or custom scheme origins can read sensitive API payloads across origins.",
                        optionalSetupSteps = "1. Authenticate as a valid user on '$targetUrl'.",
                        reproSteps = "1. Send a cross-origin request with a forged Origin header:\n   ${buildCurlCommand(targetUrl, extraHeader = "Origin: $evilOrigin")}\n2. Observe 'Access-Control-Allow-Origin: $evilOrigin' in the response.",
                        evidence = "Request Origin: $evilOrigin\nAccess-Control-Allow-Origin: $acao\nAccess-Control-Allow-Credentials: ${acac ?: "false"}",
                        solutionFix = "Replace dynamic Origin reflection with a strict server-side allowlist of trusted first-party origins, and never combine wildcard/untrusted origins with 'Access-Control-Allow-Credentials: true'."
                    )
                )
            }
            corsConn.disconnect()
        } catch (_: Exception) {
        }
        return html
    }
      // ==================== 3. JS BUNDLES & WEB3 SECRET SCANNER ====================
    private fun scanJsBundlesAndWeb3Secrets(targetUrl: String, htmlBody: String) {
        if (htmlBody.isBlank()) return
        val matcher = Pattern.compile("<script[^>]+src=[\"']([^\"']+\\.js(?:\\?[^\"']*)?)[\"']", Pattern.CASE_INSENSITIVE)
            .matcher(htmlBody)

        val scripts = linkedSetOf<String>()
        while (matcher.find() && scripts.size < 8) {
            val src = matcher.group(1) ?: continue
            scripts.add(
                when {
                    src.startsWith("http") -> src
                    src.startsWith("//") -> "https:$src"
                    src.startsWith("/") -> "$targetUrl$src"
                    else -> "$targetUrl/$src"
                }
            )
        }

        val secretRules = listOf(
            Triple("AWS Access Key ID", Pattern.compile("AKIA[0-9A-Z]{16}"), "CRITICAL" to 9.1),
            Triple("Stripe Live Secret Key", Pattern.compile("sk_live_[0-9a-zA-Z]{24,}"), "CRITICAL" to 9.1),
            Triple("Web3 / EVM Private Key Hex", Pattern.compile("(?i)(?:private[_-]?key|wallet[_-]?key|signer)[\"':=\\s]+0x[0-9a-f]{64}"), "CRITICAL" to 9.8),
            Triple("GitHub Personal Access Token", Pattern.compile("ghp_[0-9a-zA-Z]{36}"), "HIGH" to 8.2),
            Triple("Infura / Alchemy Web3 RPC Secret", Pattern.compile("(?i)(?:infura\\.io/v3/|alchemy\\.com/v2/)[0-9a-zA-Z_-]{24,}"), "MEDIUM" to 5.3),
            Triple("Google Cloud / Firebase API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"), "MEDIUM" to 5.3)
        )

        for (jsUrl in scripts) {
            try {
                val conn = openConfiguredConnection(jsUrl, followRedirects = true)
                if (conn.responseCode == 200) {
                    val js = readBodySnippet(conn, 65536)
                    for ((label, regex, sev) in secretRules) {
                        val m = regex.matcher(js)
                        if (m.find()) {
                            val raw = m.group(0) ?: ""
                            val masked = if (raw.length > 12) "${raw.take(8)}...${raw.takeLast(4)}" else raw
                            logLine("   ↳ [!] ${sev.first}: Hardcoded $label in $jsUrl")
                            addFinding(
                                VulnerabilityFinding(
                                    title = "Hardcoded $label Exposed in Client-Side JavaScript",
                                    category = if (label.contains("Web3")) "WEB3" else "INJECTION",
                                    severity = sev.first,
                                    cvssScore = sev.second,
                                    cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                                    endpoint = jsUrl,
                                    description = "The publicly served JavaScript asset '$jsUrl' contains a hardcoded $label ($masked) embedded directly in client-side source code.",
                                    securityPrivacyRisk = "Any unauthenticated attacker can extract the credential from browser DevTools or cURL and directly access cloud infrastructure, drain Web3 treasury/signer wallets, or abuse paid API quotas belonging to $lastProgramName.",
                                    mobileImpact = "If the same frontend bundle or shared SDK config is packaged inside Android APK / iOS IPA assets, attackers can extract the key via static binary decompilation.",
                                    optionalSetupSteps = "1. No authentication required; the JavaScript file is publicly accessible.",
                                    reproSteps = "1. Download the JavaScript bundle:\n   curl -s \"$jsUrl\" | grep -oE \"${regex.pattern()}\"\n2. Confirm the exposed secret prefix '$masked'.",
                                    evidence = "Bundle: $jsUrl\nMatched Secret: $label ($masked)",
                                    solutionFix = "Revoke and rotate the compromised key immediately. Move all privileged signing and API calls to a backend server and inject non-secret public identifiers via runtime environment configuration."
                                )
                            )
                        }
                    }
                }
                conn.disconnect()
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 4. XSS & SSTI INJECTION PROBER ====================
    private fun probeXssAndSsti(targetUrl: String) {
        val xssPayload = "bscope\"'><svg/onload=alert(1)>"
        val sstiPayload = "{{7*7}}bscope"
        val params = listOf("q", "search", "query", "s", "redirect", "callback")

        for (p in params) {
            // XSS Reflection Probe
            val xssUrl = "$targetUrl/?$p=${URLEncoder.encode(xssPayload, "UTF-8")}"
            try {
                val conn = openConfiguredConnection(xssUrl, followRedirects = true)
                val ct = conn.contentType ?: ""
                val body = readBodySnippet(conn, 32768)
                conn.disconnect()

                if (ct.contains("text/html", true) && body.contains(xssPayload)) {
                    logLine("   ↳ [!] HIGH: Reflected XSS via '?$p='!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Reflected Cross-Site Scripting (XSS) via '?$p=' Query Parameter",
                            category = "XSS",
                            severity = "HIGH",
                            cvssScore = 7.1,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            endpoint = "$targetUrl/?$p=",
                            description = "User-supplied input in the '?$p=' query parameter is reflected verbatim inside the 'text/html' HTTP response without HTML entity encoding or context-aware sanitization.",
                            securityPrivacyRisk = "An attacker can send a crafted URL to a $lastProgramName user; when opened, arbitrary JavaScript executes inside the victim's authenticated browser session, allowing full account takeover, CSRF token extraction, and access to private user messages/data.",
                            mobileImpact = "If opened inside an in-app WebView with JavaScript enabled, injected scripts can invoke exposed '@JavascriptInterface' bridges or steal mobile OAuth session tokens.",
                            optionalSetupSteps = "1. Open a modern web browser logged into a test account on '$targetUrl'.",
                            reproSteps = "1. Send a GET request containing unencoded HTML/SVG event characters in '?$p=':\n   ${buildCurlCommand(xssUrl)}\n2. Verify that '$xssPayload' appears unescaped in the HTML body.",
                            evidence = "Payload: $xssPayload\nReflected Unencoded in HTTP 200 text/html response.",
                            solutionFix = "Apply strict context-aware HTML entity encoding (e.g., encoding <, >, \", ', and &) on all user-controlled parameters before rendering in HTML, and enforce a nonce-based Content-Security-Policy."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }

            // SSTI Probe ({{7*7}} -> 49bscope)
            val sstiUrl = "$targetUrl/?$p=${URLEncoder.encode(sstiPayload, "UTF-8")}"
            try {
                val conn = openConfiguredConnection(sstiUrl, followRedirects = true)
                val body = readBodySnippet(conn, 32768)
                conn.disconnect()

                if (body.contains("49bscope") && !body.contains("{{7*7}}bscope")) {
                    logLine("   ↳ [!] CRITICAL: Server-Side Template Injection (SSTI) via '?$p='!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Server-Side Template Injection (SSTI) via '?$p=' Parameter",
                            category = "INJECTION",
                            severity = "CRITICAL",
                            cvssScore = 9.8,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            endpoint = "$targetUrl/?$p=",
                            description = "Mathematical template expression '{{7*7}}' supplied via '?$p=' was evaluated server-side into '49', confirming Server-Side Template Injection.",
                            securityPrivacyRisk = "SSTI frequently escalates directly to Remote Code Execution (RCE) on the underlying application server, exposing $lastProgramName production databases, internal microservices, and user data.",
                            mobileImpact = "Backend API compromise affects both web and mobile clients sharing the same server infrastructure.",
                            optionalSetupSteps = "1. No special client setup required; reproducible via standard HTTP requests.",
                            reproSteps = "1. Submit the arithmetic template canary in '?$p=':\n   ${buildCurlCommand(sstiUrl)}\n2. Confirm that the server evaluates '{{7*7}}' and outputs '49bscope'.",
                            evidence = "Sent: $sstiPayload\nEvaluated Output: 49bscope",
                            solutionFix = "Never concatenate raw user input into template strings. Pass user data strictly as sandboxed template context variables and enable template engine auto-escaping/sandbox mode."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 5. SQL INJECTION (SQLi) PROBER ====================
    private fun probeSqlInjection(targetUrl: String) {
        val sqlErrors = listOf(
            "SQL syntax.*MySQL",
            "Warning.*\\Wmysqli?_",
            "PostgreSQL.*ERROR",
            "pg_query\\(\\)",
            "Microsoft OLE DB Provider for SQL Server",
            "Unclosed quotation mark after the character string",
            "SQLite/JDBCDriver",
            "SQLiteException",
            "ORA-01756"
        )
        val params = listOf("id", "user_id", "item", "category", "page")

        for (p in params) {
            val sqliUrl = "$targetUrl/?$p=${URLEncoder.encode("1'\"", "UTF-8")}"
            try {
                val conn = openConfiguredConnection(sqliUrl, followRedirects = true)
                val code = conn.responseCode
                val body = readBodySnippet(conn, 32768)
                conn.disconnect()

                val matchedErr = sqlErrors.firstOrNull { regex ->
                    Pattern.compile(regex, Pattern.CASE_INSENSITIVE).matcher(body).find()
                }

                if (matchedErr != null) {
                    logLine("   ↳ [!] CRITICAL: Error-Based SQL Injection on '?$p='!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Error-Based SQL Injection (SQLi) in '?$p=' Parameter",
                            category = "SQLi",
                            severity = "CRITICAL",
                            cvssScore = 9.8,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            endpoint = "$targetUrl/?$p=",
                            description = "Injecting single/double quote syntax characters (`1'\"`) into the '?$p=' query parameter triggered a raw database syntax exception ($matchedErr), indicating unparameterized SQL query construction.",
                            securityPrivacyRisk = "An attacker can extract entire database tables (user credentials, PII, session tokens, private messages), modify records, or bypass authentication controls across $lastProgramName systems.",
                            mobileImpact = "Mobile API endpoints querying the same backend database expose all mobile user accounts to unauthorized extraction.",
                            optionalSetupSteps = "1. Ensure target endpoint '$targetUrl' is reachable over HTTPS.",
                            reproSteps = "1. Send a quote-breaking payload in '?$p=':\n   ${buildCurlCommand(sqliUrl)}\n2. Observe HTTP $code containing the database error signature matching '$matchedErr'.",
                            evidence = "Payload: 1'\"\nHTTP Status: $code\nDatabase Error Pattern: $matchedErr",
                            solutionFix = "Replace dynamic string concatenation with parameterized queries (Prepared Statements) or safe ORM query builders, and disable verbose database error stack traces in production."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 6. RCE / COMMAND INJECTION PROBER ====================
    private fun probeCommandInjectionRce(targetUrl: String) {
        val params = listOf("cmd", "exec", "command", "host", "ping", "ip")
        val payload = "127.0.0.1;id"

        for (p in params) {
            val rceUrl = "$targetUrl/?$p=${URLEncoder.encode(payload, "UTF-8")}"
            try {
                val conn = openConfiguredConnection(rceUrl, followRedirects = true)
                val body = readBodySnippet(conn, 16384)
                conn.disconnect()

                val uidMatcher = Pattern.compile("uid=\\d+\\([^)]+\\)\\s+gid=\\d+").matcher(body)
                if (uidMatcher.find()) {
                    val proof = uidMatcher.group(0) ?: "uid=..."
                    logLine("   ↳ [!] CRITICAL: OS Command Injection (RCE) via '?$p='!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "OS Command Injection / Remote Code Execution (RCE) via '?$p='",
                            category = "RCE",
                            severity = "CRITICAL",
                            cvssScore = 10.0,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            endpoint = "$targetUrl/?$p=",
                            description = "Shell command separator ';id' injected into the '?$p=' parameter executed on the underlying operating system and returned Unix process identity output ($proof).",
                            securityPrivacyRisk = "Complete compromise of the host server, enabling lateral movement inside $lastProgramName internal networks, theft of TLS private keys, and full access to all user data.",
                            mobileImpact = "Full backend server compromise impacts all mobile and web clients communicating with this host.",
                            optionalSetupSteps = "1. No client-side setup required beyond HTTP access to '$targetUrl'.",
                            reproSteps = "1. Execute the non-destructive command injection probe:\n   ${buildCurlCommand(rceUrl)}\n2. Verify the OS command output '$proof' in the HTTP response.",
                            evidence = "Payload: $payload\nOS Execution Proof: $proof",
                            solutionFix = "Eliminate shell invocation functions (system, exec, sh -c). Use safe language-native APIs with strict allowlist validation for network/host parameters."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 7. IDOR (INSECURE DIRECT OBJECT REFERENCE) ====================
    private fun probeIdorEndpoints(targetUrl: String) {
        val idorPairs = listOf(
            "/api/v1/users/1" to "/api/v1/users/2",
            "/api/users/1" to "/api/users/2",
            "/?user_id=1" to "/?user_id=2",
            "/?account_id=1001" to "/?account_id=1002"
        )

        val piiIndicators = listOf("\"email\"", "\"username\"", "\"phone\"", "\"address\"", "\"user_id\"")

        for ((obj1, obj2) in idorPairs) {
            try {
                val conn1 = openConfiguredConnection("$targetUrl$obj1", followRedirects = false)
                val code1 = conn1.responseCode
                val body1 = readBodySnippet(conn1, 4096)
                conn1.disconnect()

                val conn2 = openConfiguredConnection("$targetUrl$obj2", followRedirects = false)
                val code2 = conn2.responseCode
                val ct2 = conn2.contentType ?: ""
                val body2 = readBodySnippet(conn2, 4096)
                conn2.disconnect()

                val hasPii = piiIndicators.any { body2.contains(it, ignoreCase = true) }
                if (code1 == 200 && code2 == 200 && ct2.contains("json", true) && hasPii && body1 != body2) {
                    logLine("   ↳ [!] HIGH: Potential IDOR on $obj1 <-> $obj2!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Insecure Direct Object Reference (IDOR) Allowing Cross-User Data Enumeration",
                            category = "IDOR",
                            severity = "HIGH",
                            cvssScore = 7.5,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                            endpoint = "$targetUrl$obj2",
                            description = "Incrementing the numeric object identifier from '$obj1' to '$obj2' returned distinct JSON user records containing PII fields without enforcing ownership authorization.",
                            securityPrivacyRisk = "Attackers can iterate sequential user/account IDs to scrape private emails, phone numbers, and profile metadata of $lastProgramName users at scale.",
                            mobileImpact = "Mobile REST/GraphQL endpoints sharing this object-lookup controller allow any authenticated mobile app user to query other users' profiles.",
                            optionalSetupSteps = "1. Create two separate test accounts (User A and User B).\n2. Obtain User A's Authorization Bearer token or session Cookie.",
                            reproSteps = "1. Request User 1's object:\n   ${buildCurlCommand("$targetUrl$obj1")}\n2. Using the same session, request User 2's object:\n   ${buildCurlCommand("$targetUrl$obj2")}\n3. Observe HTTP 200 returning distinct user JSON data.",
                            evidence = "Object 1 ($obj1) -> HTTP $code1 (${body1.length} bytes)\nObject 2 ($obj2) -> HTTP $code2 (${body2.length} bytes, JSON PII fields matched)",
                            solutionFix = "Enforce server-side object-level authorization checks verifying that the authenticated caller owns or has explicit permission to view the requested object ID, and replace sequential integer IDs with non-guessable UUIDv4 identifiers."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }
    }

    // ==================== 8. WEB3 / JSON-RPC & SMART CONTRACT ARTIFACT AUDITOR ====================
    private fun probeWeb3Endpoints(targetUrl: String) {
        val rpcPaths = listOf("/rpc", "/eth", "/web3", "/api/rpc")
        val rpcPayload = """{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"""

        for (path in rpcPaths) {
            val rpcUrl = "$targetUrl$path"
            try {
                val conn = openConfiguredConnection(rpcUrl, followRedirects = false, method = "POST").apply {
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                }
                OutputStreamWriter(conn.outputStream).use { it.write(rpcPayload) }
                val code = conn.responseCode
                val body = readBodySnippet(conn, 2048)
                conn.disconnect()

                if (code == 200 && body.contains("\"jsonrpc\"") && body.contains("\"result\"")) {
                    logLine("   ↳ [!] HIGH: Unauthenticated Web3 Ethereum JSON-RPC Node at $path!")
                    addFinding(
                        VulnerabilityFinding(
                            title = "Unauthenticated Web3 Ethereum JSON-RPC Interface Exposed ($path)",
                            category = "WEB3",
                            severity = "HIGH",
                            cvssScore = 7.5,
                            cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            endpoint = rpcUrl,
                            description = "An Ethereum JSON-RPC endpoint is publicly accessible at '$path' without API key or IP authentication and responds to 'eth_chainId' queries.",
                            securityPrivacyRisk = "Attackers can enumerate node state, abuse paid RPC node infrastructure, query pending mempool transactions, or invoke unlocked administrative/signer JSON-RPC namespaces ('eth_accounts', 'personal_*', 'admin_*') if enabled.",
                            mobileImpact = "Mobile Web3 wallets or dApp browsers configured against this RPC endpoint can be fingerprinted or targeted if administrative namespaces are exposed.",
                            optionalSetupSteps = "1. Ensure 'curl' is available to send JSON-RPC POST requests.",
                            reproSteps = "1. Send an Ethereum JSON-RPC 'eth_chainId' request to '$rpcUrl':\n   ${buildCurlCommand(rpcUrl, method = "POST", extraHeader = "Content-Type: application/json", postJson = rpcPayload)}\n2. Verify the JSON-RPC response containing '\"result\":\"0x...\"'.",
                            evidence = "POST $rpcUrl -> HTTP $code\nResponse: ${body.take(200)}",
                            solutionFix = "Place the JSON-RPC node behind an authenticated API gateway, disable 'admin', 'debug', and 'personal' RPC namespaces, and restrict allowed JSON-RPC methods to a read-only allowlist."
                        )
                    )
                    break
                }
            } catch (_: Exception) {
            }
        }
    }
    // ==================== 9. STACK-AWARE WORDLIST & RECURSIVE CRAWLER ====================
    private fun buildStackAwareWordlist(basePaths: List<String>): List<String> {
        val combined = linkedSetOf<String>()
        combined.addAll(basePaths)
        if ("WordPress" in detectedTechStack) combined.addAll(listOf("/wp-json/wp/v2/users", "/xmlrpc.php"))
        if ("Spring Boot" in detectedTechStack) combined.addAll(listOf("/actuator", "/actuator/env", "/v3/api-docs"))
        if ("Laravel" in detectedTechStack) combined.addAll(listOf("/_ignition/health-check", "/storage/logs/laravel.log"))
        if ("Node.js" in detectedTechStack) combined.addAll(listOf("/graphql", "/package.json", "/_next/static"))
        return combined.toList()
    }

    private fun recursiveProbeWordlist(targetUrl: String, initialPaths: List<String>, maxDepth: Int) {
        var baselineStatus = 404
        var baselineLength = -1
        var baselineSig = ""
        try {
            val randomPath = "/bountyscope-404-${UUID.randomUUID().toString().take(8)}"
            val baseConn = openConfiguredConnection("$targetUrl$randomPath", followRedirects = false)
            baselineStatus = baseConn.responseCode
            val baseBody = readBodySnippet(baseConn, 2048)
            baselineLength = baseBody.length
            baselineSig = baseBody.take(160)
            baseConn.disconnect()
        } catch (_: Exception) {
        }

        val visited = mutableSetOf<String>()
        var frontier = initialPaths.distinct()
        val subDirs = listOf("/v1", "/v2", "/users", "/config", "/swagger.json", "/graphql")

        for (depth in 1..maxDepth) {
            val nextLevel = mutableListOf<String>()
            for (path in frontier) {
                val clean = if (path.startsWith("/")) path else "/$path"
                if (!visited.add(clean)) continue
                val fullUrl = "$targetUrl$clean"

                try {
                    val conn = openConfiguredConnection(fullUrl, followRedirects = false)
                    val code = conn.responseCode
                    val ct = conn.contentType ?: "unknown"
                    val snippet = readBodySnippet(conn, 2048)
                    conn.disconnect()

                    val isSoft404 = (baselineStatus == 200 && code == 200) &&
                        (kotlin.math.abs(snippet.length - baselineLength) <= 50 ||
                            (baselineSig.isNotEmpty() && snippet.startsWith(baselineSig)))

                    if (isSoft404 || code == 404) continue

                    if (depth < maxDepth && code in listOf(200, 301, 302, 401, 403) && !clean.contains(".")) {
                        val base = clean.trimEnd('/')
                        subDirs.forEach { nextLevel.add("$base$it") }
                    }

                    if (clean.contains(".env", true) && code == 200 && !ct.contains("text/html", true) && snippet.contains("=")) {
                        addFinding(
                            VulnerabilityFinding(
                                title = "Publicly Exposed Environment Configuration File ($clean)",
                                category = "INJECTION",
                                severity = "CRITICAL",
                                cvssScore = 9.8,
                                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                endpoint = fullUrl,
                                description = "The environment file '$clean' is publicly served over HTTP, exposing secret keys, database credentials, and internal service tokens.",
                                securityPrivacyRisk = "Direct compromise of production databases, cloud storage buckets, and user authentication secrets belonging to $lastProgramName.",
                                mobileImpact = "Compromised backend secrets impact all mobile and web API consumers.",
                                optionalSetupSteps = "1. None required; file is publicly accessible.",
                                reproSteps = "1. Fetch the exposed environment file:\n   ${buildCurlCommand(fullUrl)}",
                                evidence = "GET $fullUrl -> HTTP $code\nPreview:\n${snippet.take(180)}",
                                solutionFix = "Remove '$clean' from the web root immediately, rotate all credentials stored inside it, and configure the web server to deny access to all dotfiles."
                            )
                        )
                    } else if ((clean.contains(".git/config", true) || clean.contains(".git/HEAD", true)) &&
                        code == 200 && (snippet.contains("[core]") || snippet.startsWith("ref: refs/"))
                    ) {
                        addFinding(
                            VulnerabilityFinding(
                                title = "Exposed Git Repository Metadata ($clean)",
                                category = "MISCONFIG",
                                severity = "HIGH",
                                cvssScore = 7.5,
                                cvssVector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                endpoint = fullUrl,
                                description = "Git repository internals ('$clean') are publicly accessible on the web server.",
                                securityPrivacyRisk = "Allows attackers to reconstruct proprietary source code, commit history, and hardcoded secrets.",
                                mobileImpact = "Source disclosure reveals backend mobile API endpoints and signing logic.",
                                optionalSetupSteps = "1. None required.",
                                reproSteps = "1. Request '$fullUrl':\n   ${buildCurlCommand(fullUrl)}",
                                evidence = "GET $fullUrl -> HTTP 200\nBody:\n${snippet.take(180)}",
                                solutionFix = "Block public access to all '.git' directories at the web server or reverse proxy level."
                            )
                        )
                    }
                } catch (_: Exception) {
                }
            }
            if (nextLevel.isEmpty()) break
            frontier = nextLevel.distinct().take(20)
        }
    }

    // ==================== HELPERS & DNS ====================
    private fun queryGoogleDns(name: String, type: String): List<String> {
        val results = mutableListOf<String>()
        try {
            val encoded = URLEncoder.encode(name, "UTF-8")
            val conn = (URL("https://dns.google/resolve?name=$encoded&type=$type").openConnection() as HttpURLConnection).apply {
                connectTimeout = 6000
                readTimeout = 6000
            }
            if (conn.responseCode == 200) {
                val jsonText = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
                val answers = JSONObject(jsonText).optJSONArray("Answer")
                if (answers != null) {
                    for (i in 0 until answers.length()) {
                        val d = answers.getJSONObject(i).optString("data", "").trim('"')
                        if (d.isNotEmpty()) results.add(d)
                    }
                }
            }
            conn.disconnect()
        } catch (_: Exception) {
        }
        return results
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

    private fun extractApexDomain(host: String): String {
        val parts = host.split(".")
        return if (parts.size >= 2) "${parts[parts.size - 2]}.${parts[parts.size - 1]}" else host
    }
      // ==================== UI CARDS & META WHITEHAT REPORT BUILDER ====================
    private fun addFinding(finding: VulnerabilityFinding) {
        findings.add(finding)
        mainHandler.post {
            updateSeverityCounters()
            renderFindingCard(finding)
        }
    }

    private fun updateSeverityCounters() {
        critCountTxt.text = "${findings.count { it.severity == "CRITICAL" }}\nCRITICAL"
        highCountTxt.text = "${findings.count { it.severity == "HIGH" }}\nHIGH"
        medCountTxt.text = "${findings.count { it.severity == "MEDIUM" }}\nMEDIUM"
        lowCountTxt.text = "${findings.count { it.severity == "LOW" }}\nLOW"
    }

    private fun renderFindingCard(f: VulnerabilityFinding) {
        val badgeColor = when (f.severity) {
            "CRITICAL" -> critColor
            "HIGH" -> highColor
            "MEDIUM" -> medColor
            "LOW" -> lowColor
            else -> infoColor
        }

        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 18, 20, 18)
            background = roundedBox(panelBg, badgeColor, 2, 14f)
        }

        val topRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }

        val sevPill = TextView(this).apply {
            text = "${f.severity} · ${f.category} · CVSS ${f.cvssScore}"
            textSize = 10f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(if (f.severity == "CRITICAL") Color.WHITE else Color.BLACK)
            setPadding(14, 4, 14, 4)
            background = roundedBox(badgeColor, badgeColor, 0, 20f)
        }

        topRow.addView(sevPill)

        val titleTxt = TextView(this).apply {
            text = f.title
            textSize = 15f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Color.WHITE)
            setPadding(0, 10, 0, 4)
        }

        val endpointTxt = TextView(this).apply {
            text = f.endpoint
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(cyberCyan)
            setPadding(0, 0, 0, 6)
        }

        val descTxt = TextView(this).apply {
            text = f.description
            textSize = 12f
            setTextColor(Color.LTGRAY)
        }

        val viewSingleBtn = Button(this).apply {
            text = "VIEW FULL TRIAGE REPORT & REMEDIATION"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(matrixGreen)
            background = roundedBox(inputBg, matrixGreen, 1, 10f)
            setOnClickListener {
                showSingleFindingReport(f)
            }
        }

        val btnMargin = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT
        ).apply { setMargins(0, 12, 0, 0) }

        card.addView(topRow)
        card.addView(titleTxt)
        card.addView(endpointTxt)
        card.addView(descTxt)
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
        scanButton.text = "⚡ LAUNCH AUTOMATED VULNERABILITY SCAN"
        progressBar.visibility = ProgressBar.GONE

        logLine("[COMPLETE] Scan finished. Actionable findings: ${findings.size}")

        if (findings.isNotEmpty()) {
            generateReportBtn.isEnabled = true
            generateReportBtn.alpha = 1.0f
        } else {
            val cleanTxt = TextView(this).apply {
                text = "No exploitable vulnerabilities detected on $lastScannedTarget with current modules."
                textSize = 13f
                setTextColor(matrixGreen)
                setPadding(12, 12, 12, 12)
            }
            findingsContainer.addView(cleanTxt)
        }
    }

    private fun buildMarkdownReport(items: List<VulnerabilityFinding>): String {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date())
        val sb = StringBuilder()

        sb.appendLine("# Bug Bounty Vulnerability Report ($lastProgramName)")
        sb.appendLine("- **Target Asset:** `$lastScannedTarget`")
        sb.appendLine("- **Report Schema:** $reportTemplateMode")
        sb.appendLine("- **Timestamp:** $timestamp")
        sb.appendLine("- **Total Findings:** ${items.size}")
        sb.appendLine("\n---\n")

        items.forEachIndexed { idx, f ->
            sb.appendLine("## Finding #${idx + 1}: ${f.title}")
            sb.appendLine("- **Category:** `${f.category}`")
            sb.appendLine("- **Severity & CVSS v3.1:** `${f.severity}` (`${f.cvssScore}` — `${f.cvssVector}`)")
            sb.appendLine("- **Affected Endpoint:** `${f.endpoint}`\n")

            sb.appendLine("### 1. Title (Brief Description of the Issue)")
            sb.appendLine("${f.title}\n")

            sb.appendLine("### 2. Detailed Description of the Issue")
            sb.appendLine("${f.description}\n")

            sb.appendLine("### 3. Exact Security or Privacy Risk to $lastProgramName or Its Users")
            sb.appendLine("${f.securityPrivacyRisk}\n")

            sb.appendLine("### 4. Optional Information of Any Mobile-Related Issues")
            sb.appendLine("${f.mobileImpact}\n")

            sb.appendLine("### 5. Optional Setup Steps to Reproduce the Issue")
            sb.appendLine("${f.optionalSetupSteps}\n")

            sb.appendLine("### 6. Steps Required to Reproduce the Issue")
            sb.appendLine(f.reproSteps)
            sb.appendLine("\n**Captured HTTP / Technical Evidence:**")
            sb.appendLine("```text")
            sb.appendLine(f.evidence)
            sb.appendLine("```\n")

            sb.appendLine("### 7. Recommended Solution to Fix the Bug")
            sb.appendLine("${f.solutionFix}\n")
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
        showReportDialog("Full Submission Report ($lastScannedTarget)", md, lastScannedTarget)
    }

    private fun showReportDialog(dialogTitle: String, markdownContent: String, subjectTarget: String) {
        val scroll = ScrollView(this).apply { setPadding(34, 22, 34, 22) }
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
            .setPositiveButton("COPY REPORT") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Bug Bounty Report", markdownContent))
                toast("Full report copied to clipboard!")
            }
            .setNeutralButton("SHARE / EXPORT") { _, _ ->
                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_SUBJECT, "Vulnerability Report - $subjectTarget")
                    putExtra(Intent.EXTRA_TEXT, markdownContent)
                }
                startActivity(Intent.createChooser(shareIntent, "Export Vulnerability Report"))
            }
            .setNegativeButton("CLOSE", null)
            .show()
    }

    private fun refreshHistoryBadge() {
        historyBadgeBtn.text = "🗄️ VAULT (${scanDatabase.getReportCount()})"
    }

    private fun showSavedReportsDialog() {
        val savedList = scanDatabase.getAllReports()
        if (savedList.isEmpty()) {
            toast("No saved reports in offline vault yet.")
            return
        }

        val scroll = ScrollView(this).apply { setPadding(26, 18, 26, 18) }
        val listLayout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }

        savedList.forEach { report ->
            val itemCard = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(18, 14, 18, 14)
                background = roundedBox(panelBg, borderColor, 2, 12f)
            }
            val domainTxt = TextView(this).apply {
                text = "${report.targetDomain}  (${report.scannedAt})"
                textSize = 14f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.WHITE)
            }
            val progTxt = TextView(this).apply {
                text = "${report.programName} · Findings: ${report.findingsCount} (High/Crit: ${report.highCount} · Med: ${report.medCount})"
                textSize = 12f
                setTextColor(Color.LTGRAY)
                setPadding(0, 4, 0, 8)
            }
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val openBtn = Button(this).apply {
                text = "OPEN REPORT"
                textSize = 11f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(Color.BLACK)
                background = roundedBox(matrixGreen, matrixGreen, 0, 10f)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                    .apply { setMargins(0, 0, 8, 0) }
                setOnClickListener {
                    showReportDialog("Vault Report: ${report.targetDomain}", report.markdownReport, report.targetDomain)
                }
            }
            val delBtn = Button(this).apply {
                text = "DELETE"
                textSize = 11f
                setTextColor(Color.WHITE)
                background = roundedBox(critColor, critColor, 0, 10f)
                setOnClickListener {
                    scanDatabase.deleteReport(report.id)
                    refreshHistoryBadge()
                    showSavedReportsDialog()
                }
            }
            row.addView(openBtn)
            row.addView(delBtn)
            itemCard.addView(domainTxt)
            itemCard.addView(progTxt)
            itemCard.addView(row)

            val margin = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { setMargins(0, 0, 0, 10) }
            listLayout.addView(itemCard, margin)
        }

        scroll.addView(listLayout)
        AlertDialog.Builder(this)
            .setTitle("OFFLINE REPORT VAULT (${savedList.size})")
            .setView(scroll)
            .setNeutralButton("CLEAR ALL") { _, _ ->
                scanDatabase.clearAllReports()
                refreshHistoryBadge()
            }
            .setPositiveButton("CLOSE", null)
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
