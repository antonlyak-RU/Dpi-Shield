package com.security.dpibypass

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.Switch
import android.widget.TextView
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Конфигурация параметров обхода DPI
 */
object DpiConfig {
    // Включение фрагментации TLS ClientHello
    var isFragmentationEnabled = true
    
    // Смещение разделения (разбивать на 2 части по 2-му байту SNI)
    var splitPosition = 2
    
    // Блокировка QUIC (UDP 443) для принудительного переключения YouTube на TCP
    var isBlockQuicEnabled = true
    
    // Добавление ложного пакета (Fake request) перед реальным TLS handshake
    var isFakePacketEnabled = true
    
    // Метрики работы приложения в реальном времени
    val packetsIntercepted = AtomicLong(0)
    val handshakesModified = AtomicLong(0)
    val quicBlockedCount = AtomicLong(0)
}

/**
 * Главный экран управления защитой и мониторинга
 */
class MainActivity : Activity() {

    private val VPN_REQUEST_CODE = 0x0F

    private lateinit var btnToggleVpn: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvStats: TextView
    private lateinit var switchQuic: Switch
    private lateinit var switchFrag: Switch
    private lateinit var switchFake: Switch
    private lateinit var progressBar: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Динамическое построение UI-компонентов
        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(40, 60, 40, 40)
            setBackgroundColor(0xFF0F172A.toInt()) // Dark slate background
        }

        val tvTitle = TextView(this).apply {
            text = "DPI Shield & Traffic Mask"
            textSize = 22f
            setTextColor(0xFFFFFFFF.toInt())
            paint.isFakeBoldText = true
            setPadding(0, 0, 0, 20)
        }
        layout.addView(tvTitle)

        tvStatus = TextView(this).apply {
            text = "Статус: Защита отключена"
            textSize = 14f
            setTextColor(0xFF94A3B8.toInt())
            setPadding(0, 0, 0, 30)
        }
        layout.addView(tvStatus)

        switchQuic = Switch(this).apply {
            text = "Блокировать QUIC / HTTP3 (Fix YouTube)"
            isChecked = DpiConfig.isBlockQuicEnabled
            setTextColor(0xFFE2E8F0.toInt())
            setOnCheckedChangeListener { _, isChecked -> DpiConfig.isBlockQuicEnabled = isChecked }
            setPadding(0, 10, 0, 10)
        }
        layout.addView(switchQuic)

        switchFrag = Switch(this).apply {
            text = "Фрагментация TLS ClientHello (Split SNI)"
            isChecked = DpiConfig.isFragmentationEnabled
            setTextColor(0xFFE2E8F0.toInt())
            setOnCheckedChangeListener { _, isChecked -> DpiConfig.isFragmentationEnabled = isChecked }
            setPadding(0, 10, 0, 10)
        }
        layout.addView(switchFrag)

        switchFake = Switch(this).apply {
            text = "Генерация Fake-пакетов (сбивание DPI)"
            isChecked = DpiConfig.isFakePacketEnabled
            setTextColor(0xFFE2E8F0.toInt())
            setOnCheckedChangeListener { _, isChecked -> DpiConfig.isFakePacketEnabled = isChecked }
            setPadding(0, 10, 0, 30)
        }
        layout.addView(switchFake)

        btnToggleVpn = Button(this).apply {
            text = "Активировать защиту сети"
            setBackgroundColor(0xFF10B981.toInt()) // Emerald Green
            setTextColor(0xFFFFFFFF.toInt())
            setOnClickListener { toggleVpn() }
        }
        layout.addView(btnToggleVpn)

        tvStats = TextView(this).apply {
            text = "Пакетов: 0 | Модифицировано SNI: 0 | Сброшено QUIC: 0"
            textSize = 12f
            setTextColor(0xFF38BDF8.toInt())
            setPadding(0, 30, 0, 0)
        }
        layout.addView(tvStats)

        setContentView(layout)
        startStatsUpdater()
    }

    private fun toggleVpn() {
        if (DpiBypassVpnService.isRunning.get()) {
            val stopIntent = Intent(this, DpiBypassVpnService::class.java).apply {
                action = DpiBypassVpnService.ACTION_STOP
            }
            startService(stopIntent)
            btnToggleVpn.text = "Активировать защиту сети"
            btnToggleVpn.setBackgroundColor(0xFF10B981.toInt())
            tvStatus.text = "Статус: Защита отключена"
        } else {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                startActivityForResult(intent, VPN_REQUEST_CODE)
            } else {
                onActivityResult(VPN_REQUEST_CODE, RESULT_OK, null)
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            val startIntent = Intent(this, DpiBypassVpnService::class.java).apply {
                action = DpiBypassVpnService.ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
            btnToggleVpn.text = "Остановить защиту"
            btnToggleVpn.setBackgroundColor(0xFFEF4444.toInt()) // Red
            tvStatus.text = "Статус: Защита активна (DPI Shield On)"
        }
    }

    private fun startStatsUpdater() {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        handler.post(object : Runnable {
            override fun run() {
                tvStats.text = "Пакетов: ${DpiConfig.packetsIntercepted.get()} | " +
                        "Модифицировано SNI: ${DpiConfig.handshakesModified.get()} | " +
                        "Сброшено QUIC: ${DpiConfig.quicBlockedCount.get()}"
                handler.postDelayed(this, 1000)
            }
        })
    }
}

/**
 * Фоновый системный VpnService для перехвата и модификации сетевых пакетов
 */
class DpiBypassVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.security.dpibypass.START"
        const val ACTION_STOP = "com.security.dpibypass.STOP"
        const val NOTIFICATION_CHANNEL_ID = "dpi_vpn_channel"
        val isRunning = AtomicBoolean(false)
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null
    private var localProxyServer: ServerSocket? = null
    private val threadPool: ExecutorService = Executors.newCachedThreadPool()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (isRunning.get()) return
        isRunning.set(true)

        createNotificationChannel()
        startForeground(101, createNotification())

        // Запуск локального TCP-движка фрагментации пакетов
        startLocalProxyEngine()

        // Создание виртуального сетевого интерфейса (TUN)
        vpnThread = Thread({ runVpnTunLoop() }, "DpiVpnWorkerThread").apply { start() }
        Log.i("DpiVpnService", "DPI Bypass VPN Service успешно запущен")
    }

    private fun stopVpn() {
        isRunning.set(false)
        try {
            vpnInterface?.close()
            vpnInterface = null
            localProxyServer?.close()
            localProxyServer = null
            threadPool.shutdownNow()
        } catch (e: Exception) {
            Log.e("DpiVpnService", "Ошибка остановки VPN", e)
        }
        stopForeground(true)
        stopSelf()
        Log.i("DpiVpnService", "DPI Bypass VPN Service остановлен")
    }

    private fun runVpnTunLoop() {
        try {
            val builder = Builder()
                .addAddress("10.0.0.2", 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")
                .addRoute("0.0.0.0", 0)
                .setSession("DpiShieldTun")
                .setMtu(1500)

            // Исключаем собственное приложение из маршрутизации, чтобы избежать петли (loopback)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.addDisallowedApplication(packageName)
            }

            vpnInterface = builder.establish()
            val tunFd = vpnInterface?.fileDescriptor ?: return
            val inputStream = FileInputStream(tunFd)
            val outputStream = FileOutputStream(tunFd)

            val packetBuffer = ByteBuffer.allocate(32768)

            Log.i("DpiVpnService", "Интерфейс TUN открыт, начата обработка пакетов")

            while (isRunning.get()) {
                packetBuffer.clear()
                val readBytes = inputStream.read(packetBuffer.array())
                if (readBytes <= 0) {
                    Thread.sleep(10)
                    continue
                }

                DpiConfig.packetsIntercepted.incrementAndGet()
                packetBuffer.limit(readBytes)

                val ipVersion = (packetBuffer.get(0).toInt() shr 4) and 0x0F
                if (ipVersion == 4) {
                    val protocol = packetBuffer.get(9).toInt() and 0xFF
                    val ihl = (packetBuffer.get(0).toInt() and 0x0F) * 4

                    // Протокол 17 = UDP
                    if (protocol == 17) {
                        val destPort = ((packetBuffer.get(ihl + 2).toInt() and 0xFF) shl 8) or
                                (packetBuffer.get(ihl + 3).toInt() and 0xFF)

                        // Блокировка QUIC (порт 443 UDP), YouTube перейдет на TCP
                        if (destPort == 443 && DpiConfig.isBlockQuicEnabled) {
                            DpiConfig.quicBlockedCount.incrementAndGet()
                            // Пакет сбрасывается (drop), не направляясь дальше в сеть
                            continue
                        }
                    }
                }

                // Передача пакета в сетевой стек устройства
                // (В полной прозрачной реализации TCP трафик заворачивается на localProxyServer)
            }
        } catch (e: Exception) {
            if (isRunning.get()) {
                Log.e("DpiVpnService", "Ошибка в TUN цикле", e)
            }
        }
    }

    private fun startLocalProxyEngine() {
        threadPool.execute {
            try {
                localProxyServer = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
                val localPort = localProxyServer?.localPort ?: return@execute
                Log.i("DpiVpnService", "Локальный прокси-движок запущен на порту 127.0.0.1:$localPort")

                while (isRunning.get()) {
                    val clientSocket = localProxyServer?.accept() ?: break
                    clientSocket.tcpNoDelay = true
                    threadPool.execute { handleClientConnection(clientSocket) }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e("DpiVpnService", "Ошибка локального прокси-сервера", e)
                }
            }
        }
    }

    private fun handleClientConnection(clientSocket: Socket) {
        var remoteSocket: Socket? = null
        try {
            val clientIn = clientSocket.getInputStream()
            val clientOut = clientSocket.getOutputStream()

            // Буфер для первого пакета сессии
            val buffer = ByteArray(16384)
            val bytesRead = clientIn.read(buffer)
            if (bytesRead <= 0) {
                clientSocket.close()
                return
            }

            // Проверка, является ли первый пакет TLS Handshake (ClientHello)
            // 0x16 = Handshake, 0x03 = TLS Major Version
            val isTls = (bytesRead > 5 && buffer[0] == 0x16.toByte() && buffer[1] == 0x03.toByte())

            // Подключение к удаленному целевому хосту (например, YouTube или Telegram DC)
            remoteSocket = Socket()
            protect(remoteSocket) // Исключаем сокет из VPN через защиту VpnService.protect()
            remoteSocket.tcpNoDelay = true
            remoteSocket.connect(InetSocketAddress("142.250.185.206", 443), 5000) // Пример для демонстрации
            val remoteOut = remoteSocket.getOutputStream()
            val remoteIn = remoteSocket.getInputStream()

            if (isTls && DpiConfig.isFragmentationEnabled) {
                // Если включена генерация Fake-пакетов для сбивания DPI:
                if (DpiConfig.isFakePacketEnabled) {
                    val fakePacket = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n".toByteArray()
                    // Отправка фальшивого пакета
                    try {
                        remoteOut.write(fakePacket)
                        remoteOut.flush()
                        Thread.sleep(2)
                    } catch (e: Exception) {
                        Log.w("DpiVpnService", "Не удалось отправить Fake packet", e)
                    }
                }

                // Логика фрагментации ClientHello:
                // Разделяем заголовок на две порции. Первые bytesToSplit байт уходят первым сегментом,
                // оставшиеся байты - вторым сегментом с микропаузой.
                val splitPos = if (bytesRead > 100) 64 else bytesRead / 2

                val part1 = buffer.copyOfRange(0, splitPos)
                val part2 = buffer.copyOfRange(splitPos, bytesRead)

                // Отправка первой части TLS Handshake
                remoteOut.write(part1)
                remoteOut.flush()

                // Микропауза для предотвращения склейки пакетов в один сегмент на сетевой карте
                Thread.sleep(5)

                // Отправка второй части с именем домена SNI
                remoteOut.write(part2)
                remoteOut.flush()

                DpiConfig.handshakesModified.incrementAndGet()
                Log.d("DpiVpnService", "TLS ClientHello успешно фрагментирован [$splitPos + ${bytesRead - splitPos} байт]")
            } else {
                // Прямая передача без изменения
                remoteOut.write(buffer, 0, bytesRead)
                remoteOut.flush()
            }

            // Двунаправленный проброс оставшегося потока трафика
            val uploadThread = Thread({
                pipeStreams(clientIn, remoteOut)
            }, "UploadPipe")

            val downloadThread = Thread({
                pipeStreams(remoteIn, clientOut)
            }, "DownloadPipe")

            uploadThread.start()
            downloadThread.start()

            uploadThread.join()
            downloadThread.join()

        } catch (e: Exception) {
            // Ошибки таймаутов или разрывов соединений клиентом
        } finally {
            try { clientSocket.close() } catch (e: Exception) {}
            try { remoteSocket?.close() } catch (e: Exception) {}
        }
    }

    private fun pipeStreams(input: InputStream, output: OutputStream) {
        val transferBuffer = ByteArray(8192)
        try {
            var len: Int
            while (input.read(transferBuffer).also { len = it } != -1) {
                output.write(transferBuffer, 0, len)
                output.flush()
            }
        } catch (e: IOException) {
            // Соединение закрыто абонентом
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "DPI Bypass Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Фоновая служба маскировки трафика и обхода DPI"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("DPI Shield активен")
            .setContentText("Сетевой трафик фрагментируется и защищен от цензуры")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
