package com.example.bountyhunter

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class SavedScanReport(
    val id: Long,
    val programName: String,
    val targetDomain: String,
    val findingsCount: Int,
    val highCount: Int,
    val medCount: Int,
    val lowCount: Int,
    val markdownReport: String,
    val scannedAt: String
)

class ScanDatabase(context: Context) :
    SQLiteOpenHelper(context, "BountyScopeDB", null, 1) {

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE scan_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_name TEXT NOT NULL,
                target_domain TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                med_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                markdown_report TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS scan_reports")
        onCreate(db)
    }

    fun saveReport(
        programName: String,
        targetDomain: String,
        findings: List<VulnerabilityFinding>,
        markdownReport: String
    ): Long {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
        val highCount = findings.count { it.severity == "HIGH" }
        val medCount = findings.count { it.severity == "MEDIUM" }
        val lowCount = findings.count { it.severity == "LOW" }

        val values = ContentValues().apply {
            put("program_name", programName)
            put("target_domain", targetDomain)
            put("findings_count", findings.size)
            put("high_count", highCount)
            put("med_count", medCount)
            put("low_count", lowCount)
            put("markdown_report", markdownReport)
            put("scanned_at", timestamp)
        }

        return writableDatabase.insert("scan_reports", null, values)
    }

    fun getAllReports(): List<SavedScanReport> {
        val list = mutableListOf<SavedScanReport>()
        val cursor = readableDatabase.rawQuery(
            """
            SELECT id, program_name, target_domain, findings_count,
                   high_count, med_count, low_count, markdown_report, scanned_at
            FROM scan_reports
            ORDER BY id DESC
            """.trimIndent(),
            null
        )

        cursor.use {
            while (it.moveToNext()) {
                list.add(
                    SavedScanReport(
                        id = it.getLong(0),
                        programName = it.getString(1),
                        targetDomain = it.getString(2),
                        findingsCount = it.getInt(3),
                        highCount = it.getInt(4),
                        medCount = it.getInt(5),
                        lowCount = it.getInt(6),
                        markdownReport = it.getString(7),
                        scannedAt = it.getString(8)
                    )
                )
            }
        }
        return list
    }

    fun getReportCount(): Int {
        readableDatabase.rawQuery("SELECT COUNT(*) FROM scan_reports", null).use { cursor ->
            return if (cursor.moveToFirst()) cursor.getInt(0) else 0
        }
    }

    fun deleteReport(id: Long) {
        writableDatabase.delete("scan_reports", "id = ?", arrayOf(id.toString()))
    }

    fun clearAllReports() {
        writableDatabase.delete("scan_reports", null, null)
    }
    }
    
