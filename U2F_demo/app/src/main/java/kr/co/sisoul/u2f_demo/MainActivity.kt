package kr.co.sisoul.u2f_demo

import android.content.Intent
import android.nfc.Tag
import android.nfc.tech.IsoDep
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import kr.co.sisoul.u2f_demo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    lateinit var binding : ActivityMainBinding
    val nfcHandler: NFCHandler by lazy {
        NFCHandler(this)
    }
    var tag : Tag? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.d("MainActivity", "onCreate")
        binding = ActivityMainBinding.inflate(layoutInflater)

        binding.registerBtn.setOnClickListener {
            try {
                Log.d("MainActivityTAG", "register btn click")
                IsoDep.get(tag)?.use { isoDep ->
                    Log.d("MainActivityTAG", "get isodep")
                    nfcHandler.u2fSelect(isoDep, "REGISTER")
                }
            } catch(e: Exception) {
                Log.d("MainActivityTAG", "${e.message}")
            }
        }

        setContentView(binding.root)
    }

    override fun onResume() {
        super.onResume()
        Log.d("MainActivity", "onResume")
        nfcHandler.activateNfcController()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        tag = intent?.let { this.nfcHandler.getTag(it) }
    }

    override fun onPause() {
        super.onPause()
        Log.d("MainActivity", "onPause")
        nfcHandler.deActivateNfcAdapter()
    }
}