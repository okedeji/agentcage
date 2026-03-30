package com.agentcage.audit

import kotlinx.coroutines.runBlocking
import java.io.File

fun main(args: Array<String>) {
    val jdbcUrl = System.getenv("DATABASE_URL")
        ?: "jdbc:postgresql://localhost:5432/agentcage"

    val database = Database(jdbcUrl)
    val processor = Processor(database)

    if (args.isEmpty()) {
        println("usage: audit-processor <export-file.json> [export-file2.json ...]")
        println("       audit-processor --watch <directory>")
        return
    }

    if (args[0] == "--watch") {
        println("watch mode not yet implemented")
        return
    }

    runBlocking {
        val results = processor.processBatch(args.map { File(it).readText() })
        for ((index, result) in results.withIndex()) {
            result
                .onSuccess { println("${args[index]}: processed ${it.entriesProcessed} entries for cage ${it.cageId}") }
                .onFailure { println("${args[index]}: ERROR: ${it.message}") }
        }
    }
}
