package com.agentcage.audit

import kotlinx.coroutines.*
import kotlinx.serialization.json.Json

class Processor(
    private val database: Database,
    private val verifier: ChainVerifier = ChainVerifier()
) {
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun processExport(rawJson: String): Result<ProcessResult> = coroutineScope {
        val export = try {
            json.decodeFromString<AuditExport>(rawJson)
        } catch (e: Exception) {
            return@coroutineScope Result.failure(e)
        }

        verifier.verifyStructure(export.entries).onFailure {
            return@coroutineScope Result.failure(it)
        }

        val connection = database.connect()
        try {
            database.insertEntries(connection, export.entries)
        } finally {
            connection.close()
        }

        Result.success(ProcessResult(
            cageId = export.cageId,
            assessmentId = export.assessmentId,
            entriesProcessed = export.entries.size
        ))
    }

    suspend fun processBatch(exports: List<String>): List<Result<ProcessResult>> = coroutineScope {
        exports.map { rawJson ->
            async(Dispatchers.IO) { processExport(rawJson) }
        }.awaitAll()
    }
}

data class ProcessResult(
    val cageId: String,
    val assessmentId: String,
    val entriesProcessed: Int
)
