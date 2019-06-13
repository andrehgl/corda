@file:JvmName("Driver")

package net.corda.testing.driver

import net.corda.core.DoNotImplement
import net.corda.core.concurrent.CordaFuture
import net.corda.core.flows.FlowLogic
import net.corda.core.identity.Party
import net.corda.core.internal.div
import net.corda.core.internal.uncheckedCast
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.node.NetworkParameters
import net.corda.core.node.NodeInfo
import net.corda.core.node.ServiceHub
import net.corda.core.utilities.NetworkHostAndPort
import net.corda.core.utilities.getOrThrow
import net.corda.testing.common.internal.testNetworkParameters
import net.corda.testing.core.DUMMY_NOTARY_NAME
import net.corda.testing.driver.internal.incrementalPortAllocation
import net.corda.testing.driver.internal.internalServices
import net.corda.testing.node.NotarySpec
import net.corda.testing.node.TestCordapp
import net.corda.testing.node.User
import net.corda.testing.node.internal.DriverDSLImpl
import net.corda.testing.node.internal.genericDriver
import net.corda.testing.node.internal.getTimestampAsDirectoryName
import net.corda.testing.node.internal.newContext
import rx.Observable
import sun.misc.Unsafe
import sun.nio.ch.DirectBuffer
import java.io.File
import java.io.RandomAccessFile
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.Paths

/**
 * Object ecapsulating a notary started automatically by the driver.
 */
data class NotaryHandle(val identity: Party, val validating: Boolean, val nodeHandles: CordaFuture<List<NodeHandle>>)

/**
 * A base interface which represents a node as part of the [driver] dsl, extended by [InProcess] and [OutOfProcess]
 */
@DoNotImplement
interface NodeHandle : AutoCloseable {
    /** Get the [NodeInfo] for this node */
    val nodeInfo: NodeInfo
    /**
     * Interface to the node's RPC system. The first RPC user will be used to login if are any, otherwise a default one
     * will be added and that will be used.
     */
    val rpc: CordaRPCOps
    /** Get the p2p address for this node **/
    val p2pAddress: NetworkHostAndPort
    /** Get the rpc address for this node **/
    val rpcAddress: NetworkHostAndPort
    /** Get the rpc admin address for this node **/
    val rpcAdminAddress: NetworkHostAndPort
    /** Get the JMX server address for this node, if JMX is enabled **/
    val jmxAddress: NetworkHostAndPort?
    /** Get a [List] of [User]'s for this node **/
    val rpcUsers: List<User>
    /** The location of the node's base directory **/
    val baseDirectory: Path

    /**
     * Stops the referenced node.
     */
    fun stop()
}

/** Interface which represents an out of process node and exposes its process handle. **/
@DoNotImplement
interface OutOfProcess : NodeHandle {
    /** The process in which this node is running **/
    val process: Process
}

/** Interface which represents an in process node and exposes available services. **/
@DoNotImplement
interface InProcess : NodeHandle {
    /** Services which are available to this node **/
    val services: ServiceHub

    /**
     * Register a flow that is initiated by another flow
     */
    fun <T : FlowLogic<*>> registerInitiatedFlow(initiatedFlowClass: Class<T>): Observable<T>

    /**
     * Starts an already constructed flow. Note that you must be on the server thread to call this method.
     * @param context indicates who started the flow, see: [InvocationContext].
     */
    fun <T> startFlow(logic: FlowLogic<T>): CordaFuture<T> = internalServices.startFlow(logic, internalServices.newContext()).getOrThrow().resultFuture
}

/**
 * Class which represents a handle to a webserver process and its [NetworkHostAndPort] for testing purposes.
 *
 * @property listenAddress The [NetworkHostAndPort] for communicating with this webserver.
 * @property process The [Process] in which the websever is running
 * */
@Deprecated("The webserver is for testing purposes only and will be removed soon")
data class WebserverHandle(
        val listenAddress: NetworkHostAndPort,
        val process: Process
)

/**
 * An abstract helper class which is used within the driver to allocate unused ports for testing.
 */
class PortAllocation(val startingPoint: Int = 10000, fileName: File? = File(System.getProperty("user.home"), "allocator.bin")) {

    /** Get the next available port via [nextPort] and then return a [NetworkHostAndPort] **/
    fun nextHostAndPort() = NetworkHostAndPort("localhost", nextPort())

    /**
     * An implementation of [PortAllocation] which allocates ports sequentially
     */
    companion object {
        const val FIRST_EPHEMERAL_PORT = 49152L
        private val UNSAFE: Unsafe = getUnsafe()
        private fun getUnsafe(): Unsafe {
            val f = Unsafe::class.java.getDeclaredField("theUnsafe")
            f.isAccessible = true
            return f.get(null) as Unsafe
        }
    }

    private val backingFile = RandomAccessFile(fileName, "rw")
    private val mb: MappedByteBuffer = backingFile.channel.map(FileChannel.MapMode.READ_WRITE, 0, 16)
    private val startingAddress = (mb as DirectBuffer).address()

    fun nextPort(): Int {
        var oldValue: Long
        var newValue: Long
        do {
            oldValue = UNSAFE.getLongVolatile(null, startingAddress)
            newValue = if (oldValue + 1 >= FIRST_EPHEMERAL_PORT || oldValue < startingPoint) {
                //we have gone past the point of no return
                startingPoint.toLong()
            } else {
                (oldValue + 1)
            }
        } while (!UNSAFE.compareAndSwapLong(null, startingAddress, oldValue, newValue))

        return newValue.toInt()
    }

    /**
     * ONLY EVER CALL THIS FOR TESTING PURPOSES
     */
    internal fun globalReset() {
        UNSAFE.getAndSetLong(null, startingAddress, startingPoint.toLong())
    }
}

/**
 * A class containing configuration information for Jolokia JMX, to be used when creating a node via the [driver].
 *
 * @property startJmxHttpServer Indicates whether the spawned nodes should start with a Jolokia JMX agent to enable remote
 * JMX monitoring using HTTP/JSON.
 * @property jmxHttpServerPortAllocation The port allocation strategy to use for remote Jolokia/JMX monitoring over HTTP.
 * Defaults to incremental from port 7005. Use [NodeHandle.jmxAddress] to get the assigned address.
 */
@Suppress("DEPRECATION")
data class JmxPolicy
@Deprecated("Use the constructor that just takes in the jmxHttpServerPortAllocation or use JmxPolicy.defaultEnabled()")
constructor(
        val startJmxHttpServer: Boolean = false,
        val jmxHttpServerPortAllocation: PortAllocation = incrementalPortAllocation(7005)
) {
    @Deprecated("The default constructor does not turn on monitoring. Simply leave the jmxPolicy parameter unspecified if you wish to not " +
            "have monitoring turned on.")
    constructor() : this(false)

    /** Create a [JmxPolicy] that turns on monitoring using the given [PortAllocation]. */
    constructor(jmxHttpServerPortAllocation: PortAllocation) : this(true, jmxHttpServerPortAllocation)

    companion object {
        /** Returns a default [JmxPolicy] that turns on monitoring. */
        @JvmStatic
        fun defaultEnabled(): JmxPolicy = JmxPolicy(true)
    }
}

/**
 * [driver] allows one to start up nodes like this:
 *   driver {
 *     val noService = startNode(providedName = DUMMY_BANK_A.name)
 *     val notary = startNode(providedName = DUMMY_NOTARY.name)
 *
 *     (...)
 *   }
 *
 * Note that [DriverDSL.startNode] does not wait for the node to start up synchronously, but rather returns a [CordaFuture]
 * of the [NodeInfo] that may be waited on, which completes when the new node registered with the network map service or
 * loaded node data from database.
 *
 * @param defaultParameters The default parameters for the driver. Allows the driver to be configured in builder style
 *   when called from Java code.
 * @param dsl The dsl itself.
 * @return The value returned in the [dsl] closure.
 */
fun <A> driver(defaultParameters: DriverParameters = DriverParameters(), dsl: DriverDSL.() -> A): A {
    return genericDriver(
            driverDsl = DriverDSLImpl(
                    portAllocation = defaultParameters.portAllocation,
                    debugPortAllocation = defaultParameters.debugPortAllocation,
                    systemProperties = defaultParameters.systemProperties,
                    driverDirectory = defaultParameters.driverDirectory.toAbsolutePath(),
                    useTestClock = defaultParameters.useTestClock,
                    isDebug = defaultParameters.isDebug,
                    startNodesInProcess = defaultParameters.startNodesInProcess,
                    waitForAllNodesToFinish = defaultParameters.waitForAllNodesToFinish,
                    extraCordappPackagesToScan = defaultParameters.extraCordappPackagesToScan,
                    notarySpecs = defaultParameters.notarySpecs,
                    jmxPolicy = defaultParameters.jmxPolicy,
                    compatibilityZone = null,
                    networkParameters = defaultParameters.networkParameters,
                    notaryCustomOverrides = defaultParameters.notaryCustomOverrides,
                    inMemoryDB = defaultParameters.inMemoryDB,
                    cordappsForAllNodes = uncheckedCast(defaultParameters.cordappsForAllNodes)
            ),
            coerce = { it },
            dsl = dsl
    )
}

/**
 * Builder for configuring a [driver].
 *
 * @property isDebug Indicates whether the spawned nodes should start in jdwt debug mode and have debug level logging.
 * @property driverDirectory The base directory node directories go into, defaults to "build/<timestamp>/". The node
 *    directories themselves are "<baseDirectory>/<legalName>/", where legalName defaults to "<randomName>-<messagingPort>"
 *    and may be specified in [DriverDSL.startNode].
 * @property portAllocation The port allocation strategy to use for the messaging and the web server addresses. Defaults
 *    to incremental.
 * @property debugPortAllocation The port allocation strategy to use for jvm debugging. Defaults to incremental.
 * @property systemProperties A Map of extra system properties which will be given to each new node. Defaults to empty.
 * @property useTestClock If true the test clock will be used in Node.
 * @property startNodesInProcess Provides the default behaviour of whether new nodes should start inside this process or
 *     not. Note that this may be overridden in [DriverDSL.startNode].
 * @property waitForAllNodesToFinish If true, the nodes will not shut down automatically after executing the code in the
 *     driver DSL block. It will wait for them to be shut down externally instead.
 * @property notarySpecs The notaries advertised for this network. These nodes will be started automatically and will be
 *     available from [DriverDSL.notaryHandles], and will be added automatically to the network parameters.
 *     Defaults to a simple validating notary.
 * @property extraCordappPackagesToScan A [List] of additional cordapp packages to scan for any cordapp code, e.g.
 *     contract verification code, flows and services. The calling package is automatically included in this list. If this is not desirable
 *     then use [cordappsForAllNodes] instead.
 * @property jmxPolicy Used to specify whether to expose JMX metrics via Jolokia HHTP/JSON.
 * @property networkParameters The network parameters to be used by all the nodes. [NetworkParameters.notaries] must be
 *     empty as notaries are defined by [notarySpecs].
 * @property notaryCustomOverrides Extra settings that need to be passed to the notary.
 * @property inMemoryDB Whether to use in-memory H2 for new nodes rather then on-disk (the node starts quicker, however
 *     the data is not persisted between node restarts). Has no effect if node is configured
 *     in any way to use database other than H2.
 * @property cordappsForAllNodes [TestCordapp]s that will be added to each node started by the [DriverDSL].
 */
@Suppress("unused")
data class DriverParameters(
        val isDebug: Boolean = false,
        val driverDirectory: Path = Paths.get("build") / "node-driver" / getTimestampAsDirectoryName(),
        val portAllocation: PortAllocation = incrementalPortAllocation(10000),
        val debugPortAllocation: PortAllocation = incrementalPortAllocation(5005),
        val systemProperties: Map<String, String> = emptyMap(),
        val useTestClock: Boolean = false,
        val startNodesInProcess: Boolean = false,
        val waitForAllNodesToFinish: Boolean = false,
        val notarySpecs: List<NotarySpec> = listOf(NotarySpec(DUMMY_NOTARY_NAME)),
        @Deprecated("extraCordappPackagesToScan does not preserve the original CorDapp's versioning and metadata, which may lead to " +
                "misleading results in tests. Use cordappsForAllNodes instead.")
        val extraCordappPackagesToScan: List<String> = emptyList(),
        @Suppress("DEPRECATION") val jmxPolicy: JmxPolicy = JmxPolicy(),
        val networkParameters: NetworkParameters = testNetworkParameters(notaries = emptyList()),
        val notaryCustomOverrides: Map<String, Any?> = emptyMap(),
        val inMemoryDB: Boolean = true,
        val cordappsForAllNodes: Collection<TestCordapp>? = null
) {
    constructor(cordappsForAllNodes: Collection<TestCordapp>) : this(isDebug = false, cordappsForAllNodes = cordappsForAllNodes)

    constructor(
            isDebug: Boolean = false,
            driverDirectory: Path = Paths.get("build") / "node-driver" / getTimestampAsDirectoryName(),
            portAllocation: PortAllocation = incrementalPortAllocation(10000),
            debugPortAllocation: PortAllocation = incrementalPortAllocation(5005),
            systemProperties: Map<String, String> = emptyMap(),
            useTestClock: Boolean = false,
            startNodesInProcess: Boolean = false,
            waitForAllNodesToFinish: Boolean = false,
            notarySpecs: List<NotarySpec> = listOf(NotarySpec(DUMMY_NOTARY_NAME)),
            extraCordappPackagesToScan: List<String> = emptyList(),
            @Suppress("DEPRECATION") jmxPolicy: JmxPolicy = JmxPolicy(),
            networkParameters: NetworkParameters = testNetworkParameters(notaries = emptyList()),
            notaryCustomOverrides: Map<String, Any?> = emptyMap(),
            inMemoryDB: Boolean = true
    ) : this(
            isDebug,
            driverDirectory,
            portAllocation,
            debugPortAllocation,
            systemProperties,
            useTestClock,
            startNodesInProcess,
            waitForAllNodesToFinish,
            notarySpecs,
            extraCordappPackagesToScan,
            jmxPolicy,
            networkParameters,
            notaryCustomOverrides,
            inMemoryDB,
            cordappsForAllNodes = null
    )

    constructor(
            isDebug: Boolean,
            driverDirectory: Path,
            portAllocation: PortAllocation,
            debugPortAllocation: PortAllocation,
            systemProperties: Map<String, String>,
            useTestClock: Boolean,
            startNodesInProcess: Boolean,
            waitForAllNodesToFinish: Boolean,
            notarySpecs: List<NotarySpec>,
            extraCordappPackagesToScan: List<String>,
            jmxPolicy: JmxPolicy,
            networkParameters: NetworkParameters
    ) : this(
            isDebug,
            driverDirectory,
            portAllocation,
            debugPortAllocation,
            systemProperties,
            useTestClock,
            startNodesInProcess,
            waitForAllNodesToFinish,
            notarySpecs,
            extraCordappPackagesToScan,
            jmxPolicy,
            networkParameters,
            emptyMap(),
            true,
            cordappsForAllNodes = null
    )

    constructor(
            isDebug: Boolean,
            driverDirectory: Path,
            portAllocation: PortAllocation,
            debugPortAllocation: PortAllocation,
            systemProperties: Map<String, String>,
            useTestClock: Boolean,
            startNodesInProcess: Boolean,
            waitForAllNodesToFinish: Boolean,
            notarySpecs: List<NotarySpec>,
            extraCordappPackagesToScan: List<String>,
            jmxPolicy: JmxPolicy,
            networkParameters: NetworkParameters,
            inMemoryDB: Boolean
    ) : this(
            isDebug,
            driverDirectory,
            portAllocation,
            debugPortAllocation,
            systemProperties,
            useTestClock,
            startNodesInProcess,
            waitForAllNodesToFinish,
            notarySpecs,
            extraCordappPackagesToScan,
            jmxPolicy,
            networkParameters,
            emptyMap(),
            inMemoryDB,
            cordappsForAllNodes = null
    )

    fun withIsDebug(isDebug: Boolean): DriverParameters = copy(isDebug = isDebug)
    fun withDriverDirectory(driverDirectory: Path): DriverParameters = copy(driverDirectory = driverDirectory)
    fun withPortAllocation(portAllocation: PortAllocation): DriverParameters = copy(portAllocation = portAllocation)
    fun withDebugPortAllocation(debugPortAllocation: PortAllocation): DriverParameters = copy(debugPortAllocation = debugPortAllocation)
    fun withSystemProperties(systemProperties: Map<String, String>): DriverParameters = copy(systemProperties = systemProperties)
    fun withUseTestClock(useTestClock: Boolean): DriverParameters = copy(useTestClock = useTestClock)
    fun withStartNodesInProcess(startNodesInProcess: Boolean): DriverParameters = copy(startNodesInProcess = startNodesInProcess)
    fun withWaitForAllNodesToFinish(waitForAllNodesToFinish: Boolean): DriverParameters = copy(waitForAllNodesToFinish = waitForAllNodesToFinish)
    fun withNotarySpecs(notarySpecs: List<NotarySpec>): DriverParameters = copy(notarySpecs = notarySpecs)
    @Deprecated("extraCordappPackagesToScan does not preserve the original CorDapp's versioning and metadata, which may lead to " +
            "misleading results in tests. Use withCordappsForAllNodes instead.")
    fun withExtraCordappPackagesToScan(extraCordappPackagesToScan: List<String>): DriverParameters = copy(extraCordappPackagesToScan = extraCordappPackagesToScan)

    fun withJmxPolicy(jmxPolicy: JmxPolicy): DriverParameters = copy(jmxPolicy = jmxPolicy)
    fun withNetworkParameters(networkParameters: NetworkParameters): DriverParameters = copy(networkParameters = networkParameters)
    fun withNotaryCustomOverrides(notaryCustomOverrides: Map<String, Any?>): DriverParameters = copy(notaryCustomOverrides = notaryCustomOverrides)
    fun withInMemoryDB(inMemoryDB: Boolean): DriverParameters = copy(inMemoryDB = inMemoryDB)
    fun withCordappsForAllNodes(cordappsForAllNodes: Collection<TestCordapp>?): DriverParameters = copy(cordappsForAllNodes = cordappsForAllNodes)

    fun copy(
            isDebug: Boolean,
            driverDirectory: Path,
            portAllocation: PortAllocation,
            debugPortAllocation: PortAllocation,
            systemProperties: Map<String, String>,
            useTestClock: Boolean,
            startNodesInProcess: Boolean,
            waitForAllNodesToFinish: Boolean,
            notarySpecs: List<NotarySpec>,
            extraCordappPackagesToScan: List<String>,
            jmxPolicy: JmxPolicy,
            networkParameters: NetworkParameters
    ) = this.copy(
            isDebug = isDebug,
            driverDirectory = driverDirectory,
            portAllocation = portAllocation,
            debugPortAllocation = debugPortAllocation,
            systemProperties = systemProperties,
            useTestClock = useTestClock,
            startNodesInProcess = startNodesInProcess,
            waitForAllNodesToFinish = waitForAllNodesToFinish,
            notarySpecs = notarySpecs,
            extraCordappPackagesToScan = extraCordappPackagesToScan,
            jmxPolicy = jmxPolicy,
            networkParameters = networkParameters,
            notaryCustomOverrides = emptyMap()
    )

    fun copy(
            isDebug: Boolean,
            driverDirectory: Path,
            portAllocation: PortAllocation,
            debugPortAllocation: PortAllocation,
            systemProperties: Map<String, String>,
            useTestClock: Boolean,
            startNodesInProcess: Boolean,
            waitForAllNodesToFinish: Boolean,
            notarySpecs: List<NotarySpec>,
            extraCordappPackagesToScan: List<String>,
            jmxPolicy: JmxPolicy,
            networkParameters: NetworkParameters,
            cordappsForAllNodes: Set<TestCordapp>?
    ) = this.copy(
            isDebug = isDebug,
            driverDirectory = driverDirectory,
            portAllocation = portAllocation,
            debugPortAllocation = debugPortAllocation,
            systemProperties = systemProperties,
            useTestClock = useTestClock,
            startNodesInProcess = startNodesInProcess,
            waitForAllNodesToFinish = waitForAllNodesToFinish,
            notarySpecs = notarySpecs,
            extraCordappPackagesToScan = extraCordappPackagesToScan,
            jmxPolicy = jmxPolicy,
            networkParameters = networkParameters,
            notaryCustomOverrides = emptyMap(),
            cordappsForAllNodes = cordappsForAllNodes
    )
}
