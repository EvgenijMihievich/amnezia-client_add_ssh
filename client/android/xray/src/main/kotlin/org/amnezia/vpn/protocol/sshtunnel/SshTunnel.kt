package org.amnezia.vpn.protocol.sshtunnel

import android.net.VpnService.Builder
import go.Seq
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InterruptedIOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.io.FileDescriptor
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory as JavaxSocketFactory
import kotlin.text.Charsets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import org.amnezia.vpn.protocol.BadConfigException
import org.amnezia.vpn.protocol.Protocol
import org.amnezia.vpn.protocol.ProtocolState.CONNECTED
import org.amnezia.vpn.protocol.ProtocolState.DISCONNECTED
import org.amnezia.vpn.protocol.Statistics
import org.amnezia.vpn.protocol.VpnStartException
import org.amnezia.vpn.protocol.xray.XrayConfig
import org.amnezia.vpn.protocol.xray.libXray.DialerController
import org.amnezia.vpn.protocol.xray.libXray.LibXray
import org.amnezia.vpn.protocol.xray.libXray.Logger
import org.amnezia.vpn.protocol.xray.libXray.Tun2SocksConfig
import org.amnezia.vpn.util.Log
import org.amnezia.vpn.util.net.InetNetwork
import org.amnezia.vpn.util.net.parseInetAddress
import org.json.JSONObject
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider

private const val TAG = "SshTunnel"
private const val LIBXRAY_TAG = "libXray"

@Volatile
private var sshJSecurityProvidersPrepared = false

/** Android registers a minimal "BC" without X25519; sshj needs a full BouncyCastle for modern KEX. */
private fun prepareSshjSecurityProviders() {
    if (sshJSecurityProvidersPrepared) return
    synchronized(SshTunnel::class.java) {
        if (sshJSecurityProvidersPrepared) return
        try {
            Security.removeProvider("BC")
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        } catch (e: Exception) {
            Log.w(TAG, "Could not replace BC security provider for sshj: $e")
        }
        sshJSecurityProvidersPrepared = true
    }
}

private const val SOCKS5_VERSION: Byte = 0x05
private const val SOCKS5_AUTH_NONE: Byte = 0x00
private const val SOCKS5_CMD_CONNECT: Byte = 0x01
private const val SOCKS5_CMD_UDP_ASSOCIATE: Byte = 0x03
private const val SOCKS5_ATYP_IPV4: Byte = 0x01
private const val SOCKS5_ATYP_DOMAIN: Byte = 0x03
private const val SOCKS5_ATYP_IPV6: Byte = 0x04
private const val SOCKS5_REP_SUCCESS: Byte = 0x00

private fun fileDescriptorInt(fd: FileDescriptor): Int? {
    return try {
        val f = FileDescriptor::class.java.getDeclaredField("descriptor")
        f.isAccessible = true
        f.getInt(fd)
    } catch (_: ReflectiveOperationException) {
        null
    }
}

/** Best-effort FD for [VpnService.protect]; may fail on strict Android versions → caller can skip protect. */
private fun getSocketIntFd(socket: Socket): Int {
    try {
        val getImpl = Socket::class.java.getDeclaredMethod("getImpl")
        getImpl.isAccessible = true
        val impl = getImpl.invoke(socket) ?: return -1
        var c: Class<*>? = impl.javaClass
        while (c != null) {
            for (field in c.declaredFields) {
                if (!FileDescriptor::class.java.isAssignableFrom(field.type)) continue
                field.isAccessible = true
                val fdObj = field.get(impl) as? FileDescriptor ?: continue
                fileDescriptorInt(fdObj)?.let { if (it >= 0) return it }
            }
            try {
                val getFd = c.getDeclaredMethod("getFileDescriptor")
                getFd.isAccessible = true
                val fdObj = getFd.invoke(impl) as? FileDescriptor ?: break
                fileDescriptorInt(fdObj)?.let { if (it >= 0) return it }
            } catch (_: ReflectiveOperationException) {
            }
            c = c.superclass
        }
    } catch (e: Exception) {
        Log.e(TAG, "getSocketIntFd(socket): $e")
    }
    val ch = try {
        socket.channel
    } catch (_: Exception) {
        null
    }
    if (ch != null) {
        var cc: Class<*>? = ch.javaClass
        while (cc != null) {
            for (field in cc.declaredFields) {
                if (!FileDescriptor::class.java.isAssignableFrom(field.type)) continue
                field.isAccessible = true
                val fdObj = field.get(ch) as? FileDescriptor ?: continue
                fileDescriptorInt(fdObj)?.let { if (it >= 0) return it }
            }
            cc = cc.superclass
        }
    }
    return -1
}

private class ProtectingSocketFactory(private val protect: (Int) -> Boolean) : JavaxSocketFactory() {
    override fun createSocket(): Socket = ProtectingSocket(protect)

    override fun createSocket(host: String?, port: Int): Socket =
        ProtectingSocket(protect).apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        ProtectingSocket(protect).apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        ProtectingSocket(protect).apply { connect(InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        ProtectingSocket(protect).apply { connect(InetSocketAddress(address, port)) }

    private class ProtectingSocket(private val protect: (Int) -> Boolean) : Socket() {
        private var protectedFd = false

        private fun ensureProtectedBeforeConnect() {
            if (protectedFd) return
            if (!isBound) {
                reuseAddress = true
                bind(InetSocketAddress("0.0.0.0", 0))
            }
            val fd = getSocketIntFd(this)
            if (fd < 0) {
                Log.w(TAG, "Could not obtain socket FD for VPN protect(); continuing (may fail after VPN routes)")
                protectedFd = true
                return
            }
            if (!protect(fd)) {
                throw IOException("VPN protect($fd) returned false for SSH socket")
            }
            protectedFd = true
        }

        /**
         * Android: only [connect(SocketAddress, Int)] is a valid override on [Socket]; other connect overloads
         * are final / not open to Kotlin, but they delegate here (e.g. connect(addr) → connect(addr, 0)).
         */
        override fun connect(endpoint: SocketAddress?, timeout: Int) {
            ensureProtectedBeforeConnect()
            super.connect(endpoint, timeout)
        }
    }
}

private fun InputStream.readFully(buf: ByteArray, off: Int, len: Int) {
    var r = 0
    while (r < len) {
        val n = read(buf, off + r, len - r)
        if (n < 0) throw EOFException()
        r += n
    }
}

private fun InputStream.readFully(len: Int): ByteArray = ByteArray(len).also { readFully(it, 0, len) }

private fun copyStream(src: InputStream, dst: OutputStream, stop: AtomicBoolean) {
    val buf = ByteArray(32 * 1024)
    while (!stop.get()) {
        try {
            val n = src.read(buf)
            if (n < 0) break
            if (n > 0) {
                dst.write(buf, 0, n)
                dst.flush()
            }
        } catch (_: InterruptedIOException) {
            Thread.currentThread().interrupt()
            break
        } catch (_: IOException) {
            break
        }
    }
}

private fun readSocks5Destination(input: InputStream, atyp: Byte): Pair<String, Int>? {
    return when (atyp) {
        SOCKS5_ATYP_IPV4 -> {
            val ip = input.readFully(4)
            val host =
                "${ip[0].toInt() and 0xff}.${ip[1].toInt() and 0xff}.${ip[2].toInt() and 0xff}.${ip[3].toInt() and 0xff}"
            val p = input.readFully(2)
            val port = ((p[0].toInt() and 0xff) shl 8) or (p[1].toInt() and 0xff)
            host to port
        }
        SOCKS5_ATYP_DOMAIN -> {
            val len = input.read().takeIf { it >= 0 } ?: return null
            val domain = input.readFully(len)
            val host = String(domain, Charsets.US_ASCII)
            val p = input.readFully(2)
            val port = ((p[0].toInt() and 0xff) shl 8) or (p[1].toInt() and 0xff)
            host to port
        }
        SOCKS5_ATYP_IPV6 -> {
            val ip6 = input.readFully(16)
            val host = InetAddress.getByAddress(ip6).hostAddress ?: return null
            val p = input.readFully(2)
            val port = ((p[0].toInt() and 0xff) shl 8) or (p[1].toInt() and 0xff)
            host to port
        }
        else -> null
    }
}

private fun forwardDnsOverTcp(ssh: SSHClient, host: String, dnsQuery: ByteArray): ByteArray? {
    if (dnsQuery.isEmpty() || dnsQuery.size > 0xffff) return null
    val conn = try {
        ssh.newDirectConnection(host, 53)
    } catch (_: Exception) {
        return null
    }
    try {
        val out = conn.outputStream
        val n = dnsQuery.size
        out.write((n shr 8) and 0xff)
        out.write(n and 0xff)
        out.write(dnsQuery)
        out.flush()
        val inn = conn.inputStream
        val lenHi = inn.read()
        val lenLo = inn.read()
        if (lenHi < 0 || lenLo < 0) return null
        val respLen = (lenHi shl 8) or lenLo
        if (respLen <= 0 || respLen > 65535) return null
        return inn.readFully(respLen)
    } catch (_: Exception) {
        return null
    } finally {
        try {
            conn.close()
        } catch (_: IOException) {
        }
    }
}

private fun buildSocksUdpResponse(destinationHost: String, destinationPort: Int, payload: ByteArray): ByteArray {
    val addr = InetAddress.getByName(destinationHost)
    val out = ByteArrayOutputStream()
    out.write(0)
    out.write(0)
    out.write(0)
    when (addr) {
        is Inet4Address -> {
            out.write(SOCKS5_ATYP_IPV4.toInt())
            out.write(addr.address)
        }
        else -> {
            out.write(SOCKS5_ATYP_IPV6.toInt())
            out.write(addr.address)
        }
    }
    out.write((destinationPort shr 8) and 0xff)
    out.write(destinationPort and 0xff)
    out.write(payload)
    return out.toByteArray()
}

private fun decodeSocksUdpDnsAndReply(raw: ByteArray, ssh: SSHClient): ByteArray? {
    if (raw.size < 10) return null
    if (raw[0] != 0.toByte() || raw[1] != 0.toByte() || raw[2] != 0.toByte()) return null
    var o = 3
    val atyp = raw[o++]
    val (host, port, headerEnd) = when (atyp) {
        SOCKS5_ATYP_IPV4 -> {
            if (raw.size < o + 4 + 2) return null
            val h =
                "${raw[o].toInt() and 0xff}.${raw[o + 1].toInt() and 0xff}.${raw[o + 2].toInt() and 0xff}.${raw[o + 3].toInt() and 0xff}"
            o += 4
            val p = ((raw[o].toInt() and 0xff) shl 8) or (raw[o + 1].toInt() and 0xff)
            o += 2
            Triple(h, p, o)
        }
        SOCKS5_ATYP_DOMAIN -> {
            val dlen = raw[o].toInt() and 0xff
            o++
            if (raw.size < o + dlen + 2) return null
            val h = String(raw.copyOfRange(o, o + dlen), Charsets.US_ASCII)
            o += dlen
            val p = ((raw[o].toInt() and 0xff) shl 8) or (raw[o + 1].toInt() and 0xff)
            o += 2
            Triple(h, p, o)
        }
        SOCKS5_ATYP_IPV6 -> {
            if (raw.size < o + 16 + 2) return null
            val h = InetAddress.getByAddress(raw.copyOfRange(o, o + 16)).hostAddress ?: return null
            o += 16
            val p = ((raw[o].toInt() and 0xff) shl 8) or (raw[o + 1].toInt() and 0xff)
            o += 2
            Triple(h, p, o)
        }
        else -> return null
    }
    if (port != 53) return null
    if (headerEnd > raw.size) return null
    val query = raw.copyOfRange(headerEnd, raw.size)
    val answer = forwardDnsOverTcp(ssh, host, query) ?: return null
    return buildSocksUdpResponse(host, port, answer)
}

private fun relaySocks5UdpDns(tcpClient: Socket, output: OutputStream, ssh: SSHClient) {
    val udpSocket = try {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
    } catch (_: Exception) {
        return
    }
    val bindPort = udpSocket.localPort
    try {
        output.write(
            byteArrayOf(
                SOCKS5_VERSION,
                SOCKS5_REP_SUCCESS,
                0x00,
                SOCKS5_ATYP_IPV4,
                127, 0, 0, 1,
                (bindPort shr 8).toByte(),
                (bindPort and 0xff).toByte()
            )
        )
        output.flush()
    } catch (_: IOException) {
        udpSocket.close()
        return
    }
    val stop = AtomicBoolean(false)
    val buf = ByteArray(65535)
    val udpThread = Thread(
        {
            while (!stop.get()) {
                val pkt = DatagramPacket(buf, buf.size)
                try {
                    udpSocket.receive(pkt)
                } catch (_: SocketException) {
                    break
                }
                if (pkt.length <= 0) continue
                val raw = buf.copyOf(pkt.length)
                val reply = try {
                    decodeSocksUdpDnsAndReply(raw, ssh)
                } catch (_: Exception) {
                    null
                } ?: continue
                try {
                    udpSocket.send(DatagramPacket(reply, reply.size, pkt.socketAddress))
                } catch (_: IOException) {
                }
            }
        },
        "ssh-socks-udp-dns"
    )
    udpThread.start()
    try {
        val inTcp = tcpClient.getInputStream()
        val drain = ByteArray(256)
        while (true) {
            val n = inTcp.read(drain)
            if (n < 0) break
        }
    } catch (_: IOException) {
    } finally {
        stop.set(true)
        udpSocket.close()
        udpThread.interrupt()
        try {
            udpThread.join(2000)
        } catch (_: InterruptedException) {
        }
    }
}

/**
 * SSH dynamic forward (-D) equivalent: local SOCKS5 → sshj Direct TCP/IP channels → LibXray tun2socks.
 */
class SshTunnel : Protocol() {

    override val statistics: Statistics = Statistics.EMPTY_STATISTICS

    private var socksServerSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var sshClient: SSHClient? = null
    private val stopRelay = AtomicBoolean(false)
    private var isRunning = false

    override fun internalInit() {
        Seq.setContext(context)
        if (!isInitialized) {
            LibXray.initLogger(object : Logger {
                override fun warning(s: String) = Log.w(LIBXRAY_TAG, s)
                override fun error(s: String) = Log.e(LIBXRAY_TAG, s)
                override fun write(msg: ByteArray): Long {
                    Log.w(LIBXRAY_TAG, String(msg))
                    return msg.size.toLong()
                }
            }).isNotNullOrBlank { err ->
                Log.w(TAG, "Failed to initialize libXray logger: $err")
            }
        }
    }

    override suspend fun startVpn(config: JSONObject, vpnBuilder: Builder, protect: (Int) -> Boolean) {
        if (isRunning) {
            Log.w(TAG, "SSH tunnel already running")
            return
        }
        stopRelay.set(false)

        try {
            Log.i(TAG, "SSH tunnel: begin startVpn")
            val sshData = config.optJSONObject("sshtunnel_config_data")
                ?: throw BadConfigException("sshtunnel_config_data not found")
            val user = sshData.optString("userName", "amnezia_ssh")
            val password = sshData.optString("password", "")
            val sshPort = sshData.optString("port", "22022").toIntOrNull()
                ?: throw BadConfigException("invalid ssh port")
            val hostName = config.getString("hostName")
            if (user.isEmpty() || password.isEmpty()) {
                throw BadConfigException("SSH user or password is empty")
            }

            Log.i(TAG, "SSH tunnel: host=$hostName port=$sshPort user=$user")

            val xrayConfig = parseVpnInterfaceConfig(config, hostName)

            val socks = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
            socksServerSocket = socks
            val socksPort = socks.localPort
            Log.i(TAG, "SSH tunnel: SOCKS5 listening on 127.0.0.1:$socksPort")

            DialerController { protect(it.toInt()) }.also {
                LibXray.registerDialerController(it).isNotNullOrBlank { err ->
                    socks.close()
                    throw VpnStartException("Failed to register dialer controller: $err")
                }
                LibXray.registerListenerController(it).isNotNullOrBlank { err ->
                    socks.close()
                    throw VpnStartException("Failed to register listener controller: $err")
                }
            }

            buildVpnInterface(xrayConfig, vpnBuilder)

            prepareSshjSecurityProviders()
            val ssh = SSHClient(DefaultConfig())
            ssh.addHostKeyVerifier(PromiscuousVerifier())
            ssh.socketFactory = ProtectingSocketFactory(protect)

            Log.i(TAG, "SSH tunnel: connecting…")
            withContext(Dispatchers.IO) {
                ssh.connect(hostName, sshPort)
                ssh.authPassword(user, password)
            }
            Log.i(TAG, "SSH tunnel: authenticated")
            sshClient = ssh

            acceptThread = Thread({
                while (!stopRelay.get()) {
                    try {
                        val client = socks.accept()
                        Thread({
                            try {
                                handleSocks5Client(client, ssh)
                            } catch (e: Exception) {
                                Log.v(TAG, "SOCKS client: ${e.message}")
                            } finally {
                                try {
                                    client.close()
                                } catch (_: IOException) {
                                }
                            }
                        }, "ssh-socks-client").start()
                    } catch (_: SocketException) {
                        break
                    } catch (e: IOException) {
                        if (!stopRelay.get()) Log.e(TAG, "SOCKS accept: $e")
                        break
                    }
                }
            }, "ssh-socks-accept").also { it.start() }

            delay(50)

            try {
                vpnBuilder.establish().use { tunFd ->
                    if (tunFd == null) {
                        throw VpnStartException("Create VPN interface: permission not granted or revoked")
                    }
                    val fd = tunFd.detachFd()
                    val proxyUrl = "socks5://127.0.0.1:$socksPort"
                    val tun2SocksConfig = Tun2SocksConfig().apply {
                        mtu = xrayConfig.mtu.toLong()
                        proxy = proxyUrl
                        device = "fd://$fd"
                        logLevel = "warn"
                    }
                    Log.i(TAG, "SSH tunnel: starting tun2socks mtu=${xrayConfig.mtu}")
                    LibXray.startTun2Socks(tun2SocksConfig, fd.toLong()).isNotNullOrBlank { err ->
                        throw VpnStartException("Failed to start tun2socks: $err")
                    }
                }
            } catch (e: Exception) {
                stopInternal()
                throw e
            }

            Log.i(TAG, "SSH tunnel: connected")
            state.value = CONNECTED
            isRunning = true
        } catch (e: BadConfigException) {
            Log.e(TAG, "SSH tunnel config error: $e")
            throw e
        } catch (e: VpnStartException) {
            Log.e(TAG, "SSH tunnel start error: $e")
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "SSH tunnel failed: $e")
            throw VpnStartException("SSH tunnel: ${e.javaClass.simpleName}: ${e.message}", e)
        }
    }

    private fun parseVpnInterfaceConfig(config: JSONObject, hostName: String): XrayConfig {
        val resolved = try {
            parseInetAddress(hostName)
        } catch (_: Exception) {
            throw BadConfigException("Cannot resolve hostName for routes: $hostName")
        }
        val bypassIp = resolved.hostAddress
            ?: throw BadConfigException("Cannot get host address after resolve: $hostName")
        val bypass = InetNetwork(
            bypassIp,
            if (resolved is Inet6Address) 128 else 32
        )
        return XrayConfig.build {
            addAddress(InetNetwork("10.33.0.2", 30))
            config.optString("dns1").trim().takeIf { it.isNotEmpty() }?.let {
                addDnsServer(parseInetAddress(it))
            }
            config.optString("dns2").trim().takeIf { it.isNotEmpty() }?.let {
                addDnsServer(parseInetAddress(it))
            }
            addRoute(InetNetwork("0.0.0.0", 0))
            addRoute(InetNetwork("2000::", 3))
            excludeRoute(bypass)
            config.optString("mtu").trim().takeIf { it.isNotEmpty() }?.let { setMtu(it.toInt()) }
            setSocksPort(0)
            setSocksUser("")
            setSocksPass("")
            configSplitTunneling(config)
            configAppSplitTunneling(config)
        }
    }

    private fun handleSocks5Client(client: Socket, ssh: SSHClient) {
        client.tcpNoDelay = true
        val input = client.getInputStream()
        val output = client.getOutputStream()

        val verNmethods = input.readFully(2)
        if (verNmethods[0] != SOCKS5_VERSION) return
        val nMethods = verNmethods[1].toInt() and 0xff
        if (nMethods <= 0) return
        val methods = input.readFully(nMethods)
        val methodSelected =
            if (methods.any { (it.toInt() and 0xff) == (SOCKS5_AUTH_NONE.toInt() and 0xff) }) {
                SOCKS5_AUTH_NONE
            } else {
                0xFF.toByte()
            }
        output.write(byteArrayOf(SOCKS5_VERSION, methodSelected))
        output.flush()
        if (methodSelected == 0xFF.toByte()) {
            return
        }

        val header = input.readFully(4)
        if (header[0] != SOCKS5_VERSION) return
        when (header[1]) {
            SOCKS5_CMD_UDP_ASSOCIATE -> {
                if (readSocks5Destination(input, header[3]) == null) {
                    replySocksFail(output, 0x08.toByte())
                    return
                }
                relaySocks5UdpDns(client, output, ssh)
                return
            }
            SOCKS5_CMD_CONNECT -> {
                val (targetHost, targetPort) = readSocks5Destination(input, header[3]) ?: run {
                    replySocksFail(output, 0x08.toByte())
                    return
                }
                val direct = try {
                    ssh.newDirectConnection(targetHost, targetPort)
                } catch (e: Exception) {
                    Log.w(TAG, "DirectConnection $targetHost:$targetPort failed: $e")
                    replySocksFail(output, 0x05.toByte())
                    return
                }

                output.write(
                    byteArrayOf(
                        SOCKS5_VERSION,
                        SOCKS5_REP_SUCCESS,
                        0x00,
                        SOCKS5_ATYP_IPV4,
                        0, 0, 0, 0,
                        0, 0
                    )
                )
                output.flush()

                val remoteIn = direct.inputStream
                val remoteOut = direct.outputStream
                val stop = AtomicBoolean(false)
                val t1 = Thread({ copyStream(input, remoteOut, stop) }, "ssh-socks-up")
                val t2 = Thread({ copyStream(remoteIn, output, stop) }, "ssh-socks-down")
                t1.start()
                t2.start()
                try {
                    t1.join()
                } finally {
                    stop.set(true)
                    try {
                        direct.close()
                    } catch (_: IOException) {
                    }
                    t2.interrupt()
                    t2.join(2000)
                }
            }
            else -> {
                replySocksFail(output, 0x07.toByte())
                return
            }
        }
    }

    private fun replySocksFail(output: OutputStream, rep: Byte) {
        try {
            output.write(byteArrayOf(SOCKS5_VERSION, rep, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0))
            output.flush()
        } catch (_: IOException) {
        }
    }

    override fun stopVpn() {
        stopRelay.set(true)
        try {
            socksServerSocket?.close()
        } catch (_: IOException) {
        }
        socksServerSocket = null

        try {
            acceptThread?.join(3000)
        } catch (_: InterruptedException) {
        }
        acceptThread = null

        try {
            sshClient?.disconnect()
        } catch (_: IOException) {
        }
        sshClient = null

        LibXray.stopTun2Socks().isNotNullOrBlank { err ->
            Log.e(TAG, "Failed to stop tun2socks: $err")
        }

        isRunning = false
        state.value = DISCONNECTED
    }

    private fun stopInternal() {
        stopRelay.set(true)
        try {
            socksServerSocket?.close()
        } catch (_: IOException) {
        }
        socksServerSocket = null
        try {
            acceptThread?.join(1500)
        } catch (_: InterruptedException) {
        }
        acceptThread = null
        try {
            sshClient?.disconnect()
        } catch (_: IOException) {
        }
        sshClient = null
        LibXray.stopTun2Socks()
        isRunning = false
    }

    override fun reconnectVpn(vpnBuilder: Builder, protect: (Int) -> Boolean) {
        state.value = CONNECTED
    }
}

private fun String?.isNotNullOrBlank(block: (String) -> Unit) {
    if (!this.isNullOrBlank()) {
        block(this)
    }
}
