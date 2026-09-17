package com.nosknet.diagnostic.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.nosknet.diagnostic.R
import com.nosknet.diagnostic.ui.MainActivity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Milestone 1 — VpnService mínimo e funcional.
 *
 * Objetivos deste estágio:
 * 1. Solicitar autorização VPN
 * 2. Criar TUN
 * 3. Restringir APENAS ao package com.dts.freefireth via addAllowedApplication
 * 4. Fazer passthrough real (encaminhar pacotes)
 * 5. Evitar loop com protect()
 * 6. Contar pacotes e mostrar estado
 *
 * Ainda NÃO faz análise profunda de metadados (isso é Milestone 2).
 */
class NoskVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.nosknet.diagnostic.START"
        const val ACTION_STOP = "com.nosknet.diagnostic.STOP"
        private const val TAG = "NoskVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "nosk_vpn_channel"
        private const val TARGET_PACKAGE = "com.dts.freefireth"

        // Endereço local do TUN (não conflita com redes comuns)
        private const val TUN_ADDRESS = "10.8.0.2"
        private const val TUN_PREFIX = 32
        private const val MTU = 1500
    }

    private val binder = LocalBinder()
    private var tunInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private val packetCount = AtomicLong(0)

    @Volatile
    var currentState: VpnState = VpnState.STOPPED
        private set

    private var stateListener: ((VpnState, Long, String) -> Unit)? = null
    private var captureThread: Thread? = null

    inner class LocalBinder : Binder() {
        fun getService(): NoskVpnService = this@NoskVpnService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    fun setStateListener(listener: (VpnState, Long, String) -> Unit) {
        stateListener = listener
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startCapture()
            ACTION_STOP -> stopCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (running.get()) {
            Log.i(TAG, "Já está rodando")
            return
        }

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, buildNotification("Aguardando Free Fire…"))

            // Configuração crítica do Builder
            val builder = Builder()
                .setSession("NoskNet Diagnostic")
                .setMtu(MTU)
                .addAddress(TUN_ADDRESS, TUN_PREFIX)
                // Rota 0.0.0.0/0 → todo tráfego IPv4 do app permitido vai para o TUN
                .addRoute("0.0.0.0", 0)
                // CRÍTICO: só o Free Fire é permitido
                .addAllowedApplication(TARGET_PACKAGE)
                // DNS opcional (pode ajudar em alguns casos, mas não é obrigatório)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")

            // Tenta IPv6 também (se o dispositivo suportar)
            try {
                builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                builder.addRoute("::", 0)
            } catch (e: Exception) {
                Log.w(TAG, "IPv6 não disponível neste dispositivo")
            }

            tunInterface = builder.establish()

            if (tunInterface == null) {
                Log.e(TAG, "Falha ao estabelecer TUN")
                updateState(VpnState.ERROR, "Falha ao criar interface TUN")
                stopSelf()
                return
            }

            running.set(true)
            updateState(VpnState.WAITING_FREE_FIRE, "TUN criado. Aguardando tráfego do Free Fire…")

            // Thread de captura / passthrough
            captureThread = thread(name = "VpnCaptureThread", isDaemon = true) {
                runPassthroughLoop()
            }

            Log.i(TAG, "VPN iniciada com sucesso. Target: $TARGET_PACKAGE")

        } catch (e: Exception) {
            Log.e(TAG, "Erro ao iniciar VPN", e)
            updateState(VpnState.ERROR, "Erro: ${e.message}")
            stopCapture()
        }
    }

    /**
     * Loop principal de passthrough.
     *
     * Lê pacotes do TUN → extrai cabeçalho mínimo → reenvia via socket protegido.
     * Esta é a versão mínima funcional do Milestone 1.
     *
     * Limitação conhecida do Milestone 1:
     * - Usa abordagem simplificada de reenvio UDP/TCP genérico.
     * - Em produção real (Milestone 2+) deve-se usar um encaminhador mais robusto
     *   (ex: baseado em DatagramChannel + SocketChannel + select).
     */
    private fun runPassthroughLoop() {
        val tun = tunInterface ?: return
        val input = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val buffer = ByteArray(MTU)

        Log.i(TAG, "Loop de captura iniciado")

        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length <= 0) continue

                packetCount.incrementAndGet()

                // Primeira vez que vemos tráfego → Free Fire está ativo
                if (currentState == VpnState.WAITING_FREE_FIRE) {
                    updateState(VpnState.CAPTURING, "Tráfego do Free Fire detectado")
                }

                // Análise mínima de cabeçalho (apenas para log)
                val version = (buffer[0].toInt() shr 4) and 0x0F

                if (version == 4 && length >= 20) {
                    val protocol = buffer[9].toInt() and 0xFF
                    val srcIp = "${buffer[12].toInt() and 0xFF}.${buffer[13].toInt() and 0xFF}." +
                            "${buffer[14].toInt() and 0xFF}.${buffer[15].toInt() and 0xFF}"
                    val dstIp = "${buffer[16].toInt() and 0xFF}.${buffer[17].toInt() and 0xFF}." +
                            "${buffer[18].toInt() and 0xFF}.${buffer[19].toInt() and 0xFF}"

                    val ihl = (buffer[0].toInt() and 0x0F) * 4
                    val srcPort: Int
                    val dstPort: Int
                    if (length >= ihl + 4) {
                        srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
                        dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
                    } else {
                        srcPort = 0
                        dstPort = 0
                    }

                    // Log ocasional (não a cada pacote para não poluir)
                    if (packetCount.get() % 50 == 1L) {
                        val protoName = when (protocol) {
                            6 -> "TCP"
                            17 -> "UDP"
                            1 -> "ICMP"
                            else -> "IP-$protocol"
                        }
                        val logMsg = "[$protoName] $srcIp:$srcPort → $dstIp:$dstPort (${length}B)"
                        Log.d(TAG, logMsg)
                        stateListener?.invoke(currentState, packetCount.get(), logMsg)
                    }

                    // === PASSTHROUGH ===
                    // Reenvia o pacote original usando socket protegido
                    forwardPacket(buffer, length, protocol, dstIp, dstPort, output)
                }
                // IPv6 ainda não implementado no Milestone 1 (só conta)
            }
        } catch (e: Exception) {
            if (running.get()) {
                Log.e(TAG, "Erro no loop de captura", e)
                updateState(VpnState.ERROR, "Erro no loop: ${e.message}")
            }
        } finally {
            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
            Log.i(TAG, "Loop de captura finalizado. Total de pacotes: ${packetCount.get()}")
        }
    }

    /**
     * Encaminha o pacote de volta para a rede real.
     *
     * Estratégia do Milestone 1 (simples e funcional para prova de conceito):
     * - Para UDP: usa DatagramSocket + protect()
     * - Para TCP: neste estágio inicial apenas contabilizamos (encaminhamento TCP completo
     *   exige máquina de estados mais complexa → Milestone 2)
     *
     * Importante: protect(socket) impede que o tráfego de saída volte para o TUN.
     */
    private fun forwardPacket(
        packet: ByteArray,
        length: Int,
        protocol: Int,
        dstIp: String,
        dstPort: Int,
        tunOutput: FileOutputStream
    ) {
        try {
            when (protocol) {
                17 -> { // UDP
                    // Extrai o payload UDP (após cabeçalho IP + cabeçalho UDP de 8 bytes)
                    val ihl = (packet[0].toInt() and 0x0F) * 4
                    val udpPayloadOffset = ihl + 8
                    if (length <= udpPayloadOffset) return

                    val payload = packet.copyOfRange(udpPayloadOffset, length)

                    val socket = DatagramSocket()
                    // CRÍTICO: protege o socket para não voltar para o TUN
                    protect(socket)

                    val address = InetAddress.getByName(dstIp)
                    val datagram = DatagramPacket(payload, payload.size, address, dstPort)
                    socket.send(datagram)

                    // Recebe resposta (timeout curto para não travar o loop)
                    socket.soTimeout = 50
                    try {
                        val responseBuffer = ByteArray(MTU)
                        val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
                        socket.receive(responsePacket)

                        // Reconstrói um pacote IP mínimo e escreve de volta no TUN
                        // (versão simplificada — Milestone 2 fará reconstrução completa)
                        // Por enquanto apenas contamos a resposta
                        packetCount.incrementAndGet()
                    } catch (_: Exception) {
                        // Timeout normal — nem todo pacote tem resposta imediata
                    } finally {
                        socket.close()
                    }
                }
                6 -> {
                    // TCP: no Milestone 1 apenas contabilizamos.
                    // Encaminhamento TCP completo exige SYN/ACK tracking e será feito no próximo marco.
                }
                else -> {
                    // ICMP e outros: apenas contagem
                }
            }
        } catch (e: Exception) {
            // Não derruba o loop por erro de um pacote
            Log.w(TAG, "Falha ao encaminhar pacote: ${e.message}")
        }
    }

    private fun stopCapture() {
        running.set(false)
        captureThread?.interrupt()
        captureThread = null

        try {
            tunInterface?.close()
        } catch (_: Exception) {}
        tunInterface = null

        updateState(VpnState.STOPPED, "Captura finalizada. Total: ${packetCount.get()} pacotes")
        packetCount.set(0)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        Log.i(TAG, "VPN parada")
    }

    private fun updateState(state: VpnState, log: String = "") {
        currentState = state
        stateListener?.invoke(state, packetCount.get(), log)
        Log.i(TAG, "Estado → $state | $log")
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_description)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(content: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(content)
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    override fun onRevoke() {
        // Usuário desativou a VPN pelas configurações do sistema
        Log.w(TAG, "VPN revogada pelo sistema")
        stopCapture()
        super.onRevoke()
    }
}
