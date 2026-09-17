package com.nosknet.diagnostic.ui

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.nosknet.diagnostic.databinding.ActivityMainBinding
import com.nosknet.diagnostic.service.NoskVpnService
import com.nosknet.diagnostic.service.VpnState

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var vpnService: NoskVpnService? = null
    private var bound = false

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "Permissão de VPN negada", Toast.LENGTH_LONG).show()
            updateUi(VpnState.ERROR)
        }
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as NoskVpnService.LocalBinder
            vpnService = binder.getService()
            bound = true
            vpnService?.setStateListener { state, packets, log ->
                runOnUiThread {
                    updateUi(state)
                    binding.tvPacketCount.text = "Pacotes: $packets"
                    if (log.isNotBlank()) {
                        binding.tvLastLog.text = log
                    }
                }
            }
            // Força atualização imediata
            vpnService?.let {
                updateUi(it.currentState)
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            bound = false
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnStartVpn.setOnClickListener {
            requestVpnPermissionAndStart()
        }

        binding.btnStopVpn.setOnClickListener {
            stopVpnService()
        }
    }

    override fun onStart() {
        super.onStart()
        Intent(this, NoskVpnService::class.java).also { intent ->
            bindService(intent, connection, Context.BIND_AUTO_CREATE)
        }
    }

    override fun onStop() {
        super.onStop()
        if (bound) {
            unbindService(connection)
            bound = false
        }
    }

    private fun requestVpnPermissionAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // Já tem permissão
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, NoskVpnService::class.java).apply {
            action = NoskVpnService.ACTION_START
        }
        startForegroundService(intent)
        updateUi(VpnState.WAITING_FREE_FIRE)
    }

    private fun stopVpnService() {
        val intent = Intent(this, NoskVpnService::class.java).apply {
            action = NoskVpnService.ACTION_STOP
        }
        startService(intent)
        updateUi(VpnState.STOPPED)
    }

    private fun updateUi(state: VpnState) {
        binding.tvVpnStatus.text = when (state) {
            VpnState.STOPPED -> "VPN: DESLIGADA"
            VpnState.WAITING_FREE_FIRE -> "VPN: AGUARDANDO FREE FIRE"
            VpnState.ACTIVE -> "VPN: ATIVA — FREE FIRE DETECTADO"
            VpnState.CAPTURING -> "VPN: CAPTURANDO"
            VpnState.ERROR -> "VPN: ERRO"
        }

        val color = when (state) {
            VpnState.STOPPED -> getColor(android.R.color.darker_gray)
            VpnState.WAITING_FREE_FIRE -> getColor(android.R.color.holo_orange_light)
            VpnState.ACTIVE, VpnState.CAPTURING -> getColor(android.R.color.holo_green_light)
            VpnState.ERROR -> getColor(android.R.color.holo_red_light)
        }
        binding.tvVpnStatus.setTextColor(color)

        binding.btnStartVpn.isEnabled = state == VpnState.STOPPED || state == VpnState.ERROR
        binding.btnStopVpn.isEnabled = state != VpnState.STOPPED

        binding.tvFreeFireStatus.text = when (state) {
            VpnState.ACTIVE, VpnState.CAPTURING -> "Free Fire: DETECTADO"
            VpnState.WAITING_FREE_FIRE -> "Free Fire: aguardando..."
            else -> "Free Fire: não detectado"
        }
    }
}
