package com.agentcage.audit

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName

@Serializable
data class AuditExport(
    @SerialName("cage_id") val cageId: String,
    @SerialName("assessment_id") val assessmentId: String,
    val entries: List<AuditEntry>,
    val digest: AuditDigest? = null,
    @SerialName("exported_at") val exportedAt: String
)

@Serializable
data class AuditEntry(
    val id: String,
    @SerialName("cage_id") val cageId: String,
    @SerialName("assessment_id") val assessmentId: String,
    val sequence: Long,
    val type: String,
    val timestamp: String,
    val data: String? = null,
    @SerialName("key_version") val keyVersion: String,
    val signature: String,
    @SerialName("previous_hash") val previousHash: String
)

@Serializable
data class AuditDigest(
    @SerialName("assessment_id") val assessmentId: String,
    @SerialName("cage_id") val cageId: String,
    @SerialName("chain_head_hash") val chainHeadHash: String,
    @SerialName("entry_count") val entryCount: Long,
    @SerialName("key_version") val keyVersion: String,
    val signature: String,
    @SerialName("issued_at") val issuedAt: String
)
