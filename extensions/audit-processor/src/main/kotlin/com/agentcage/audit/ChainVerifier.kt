package com.agentcage.audit

class ChainVerificationError(message: String) : Exception(message)

class ChainVerifier {
    // Verify sequence continuity and entry completeness.
    // Full HMAC verification requires signing keys from Vault --
    // use the Go audit.VerifyChain function for cryptographic verification.
    fun verifyStructure(entries: List<AuditEntry>): Result<Unit> {
        if (entries.isEmpty()) return Result.failure(ChainVerificationError("empty chain"))

        for ((index, entry) in entries.withIndex()) {
            val expected = (index + 1).toLong()
            if (entry.sequence != expected) {
                return Result.failure(
                    ChainVerificationError("sequence gap: expected $expected, got ${entry.sequence}")
                )
            }
            if (entry.id.isBlank()) {
                return Result.failure(
                    ChainVerificationError("entry ${entry.sequence} has blank ID")
                )
            }
            if (entry.keyVersion.isBlank()) {
                return Result.failure(
                    ChainVerificationError("entry ${entry.sequence} has blank key version")
                )
            }
        }
        return Result.success(Unit)
    }
}
