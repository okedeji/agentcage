package com.agentcage.audit

import java.sql.Connection
import java.sql.DriverManager

class Database(private val jdbcUrl: String) {

    fun connect(): Connection = DriverManager.getConnection(jdbcUrl)

    fun insertEntries(connection: Connection, entries: List<AuditEntry>) {
        val sql = """
            INSERT INTO audit_entries (id, cage_id, assessment_id, sequence, entry_type, timestamp, data, key_version, signature, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?::timestamptz, ?::jsonb, ?, decode(?, 'base64'), decode(?, 'base64'))
            ON CONFLICT (cage_id, sequence) DO NOTHING
        """.trimIndent()

        connection.prepareStatement(sql).use { stmt ->
            for (entry in entries) {
                stmt.setString(1, entry.id)
                stmt.setString(2, entry.cageId)
                stmt.setString(3, entry.assessmentId)
                stmt.setLong(4, entry.sequence)
                stmt.setString(5, entry.type)
                stmt.setString(6, entry.timestamp)
                stmt.setString(7, entry.data)
                stmt.setString(8, entry.keyVersion)
                stmt.setString(9, entry.signature)
                stmt.setString(10, entry.previousHash)
                stmt.addBatch()
            }
            stmt.executeBatch()
        }
    }
}
