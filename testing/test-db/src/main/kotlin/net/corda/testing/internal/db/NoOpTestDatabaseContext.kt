package net.corda.testing.internal.db

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * An implementation of [TestDatabaseContext] which does nothing besides logging the calls made to it.
 */
class NoOpTestDatabaseContext : TestDatabaseContext {

    companion object {
        private val logger: Logger = LoggerFactory.getLogger(NoOpTestDatabaseContext::class.java)
    }

    private lateinit var groupName: String

    override fun initialize(groupName: String) {
        logger.trace("[NO-OP] Initializing database group $groupName")
        this.groupName = groupName
    }

    override fun beforeClass(setupSql: String) {
        logger.trace("[NO-OP] Running SQL setup script $setupSql in group $groupName")
    }

    override fun afterClass(teardownSql: String) {
        logger.trace("[NO-OP] Running SQL teardown script $teardownSql in group $groupName")
    }

    override fun beforeTest(setupSql: String) {
        logger.trace("[NO-OP] Running SQL setup script $setupSql in group $groupName")
    }

    override fun afterTest(teardownSql: String) {
        logger.trace("[NO-OP] Running SQL teardown script $teardownSql in group $groupName")
    }

    override fun close() {
        logger.trace("[NO-OP] Cleaning up database group $groupName")
    }
}