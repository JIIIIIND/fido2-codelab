package kr.co.sisoul.u2f_demo

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.graphics.PorterDuff
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.*
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kr.co.sisoul.sisoultaginfo.fingerPrint.*
import java.security.DigestException
import java.security.MessageDigest
import java.util.*

class NFCHandler(activity: Activity) {
    private val TAG = "NFC_HANDLER"
    private var activity : Activity? = activity
    private var nfcAdapter : NfcAdapter? = null
    private var tag : Tag? = null

    init {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this.activity)
        if (this.nfcAdapter == null)
            Toast.makeText(activity, "NFC를 지원하지 않습니다.", Toast.LENGTH_SHORT).show()
    }

    fun activateNfcController() : Unit {
        Log.d(TAG, "Activate NFC")
        if (this.nfcAdapter != null && this.activity != null) {
            val targetIntent = Intent(this.activity, this.activity!!::class.java)
            targetIntent.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            //pending
            val pendingIntent = PendingIntent.getActivities(this.activity, 0, arrayOf(targetIntent), 0)
            //intentFilter
            val intentFilter : Array<IntentFilter>? = arrayOf(IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED))
            val techLists = arrayOf(
                arrayOf(NfcA::class.java.name),
                arrayOf(NfcF::class.java.name),
                arrayOf(NfcV::class.java.name),
                arrayOf(NfcB::class.java.name))
            //techLists
            nfcAdapter!!.enableForegroundDispatch(this.activity, pendingIntent, intentFilter, techLists)
        }
    }

    fun deActivateNfcAdapter() {
        Log.d(TAG, "deActivate NFC")
        if (this.nfcAdapter != null)
            this.nfcAdapter!!.disableForegroundDispatch(this.activity)
    }

    fun getTag(intent : Intent) : Tag? {
//        Log.d(TAG, "setTag")
        this.tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        if (this.tag == null) {
            Toast.makeText(this.activity, "NFC Tag 실패", Toast.LENGTH_SHORT).show()
            return null
        }
        Toast.makeText(this.activity, "NFC Tag 성공", Toast.LENGTH_SHORT).show()
        return this.tag
    }

    fun ByteArray.toHex(): String = joinToString() { eachByte ->
        "%02x".format(eachByte)
    }

    fun getSHA256(msg: String): ByteArray {
        val hash: ByteArray
        try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(msg.toByteArray())
            hash = md.digest()
        } catch (e: CloneNotSupportedException) {
            throw DigestException("couldn't make digest of partial content")
        }
        return hash
    }

    fun u2f_authenticate() {
        val challenge = getSHA256("test")
        val appParam = getSHA256("http://sisoul.co.kr")

    }

    val SELECT_U2F = byteArrayOf(
        0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(), 0x08.toByte(), 0xA0.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x06.toByte(), 0x047.toByte(), 0x2F.toByte(), 0x00.toByte(), 0x01.toByte()
    )

    fun u2fSelect(isoDep: IsoDep, command: String) {
        var result = STATUS.FAIL
        if (!isoDep.isConnected)
            isoDep.connect()
        try {
            isoDep.use {tech ->
                val receiveData = isoDep.transceive(SELECT_U2F)
                if (receiveData.size >= 2 &&
                    receiveData[receiveData.size - 2] == 0x90.toByte() &&
                    receiveData[receiveData.size - 1] == 0x00.toByte()) {
                    Log.d(TAG, "SELECT OK")
                    when (command) {
                        "REGISTER" -> u2fRegister(isoDep)
                        else -> Log.d(TAG, "command not found")
                    }
                }
                else
                    Log.d(TAG, "fail: ${receiveData.toHex()}")
            }
        } catch (e : Exception) {
            e.message?.let { Log.d(TAG, it) }
        }
        isoDep.close()
    }

    fun u2fRegister(isoDep: IsoDep) {
        val challenge = getSHA256("test")
        val appParam = getSHA256("http://sisoul.co.kr")
        val apdu = ByteArray(69)
        apdu[1] = 0x01.toByte()
        apdu[2] = 0x03.toByte()
        apdu[4] = 0x40.toByte()
        challenge.copyInto(apdu, 5, 0)
        appParam.copyInto(apdu, 5 + 32, 0)

        Log.d(TAG, "challenge: ${challenge.toHex()}")
        Log.d(TAG, "appParam: ${appParam.toHex()}")
        Log.d(TAG, "apdu: ${apdu.toHex()}")

        var result = STATUS.FAIL
        if (!isoDep.isConnected)
            isoDep.connect()
        try {
            isoDep.use {tech ->
                val receiveData = isoDep.transceive(apdu)
                if (receiveData.size >= 2 &&
                    receiveData[receiveData.size - 2] == 0x90.toByte() &&
                    receiveData[receiveData.size - 1] == 0x00.toByte()) {
                    Log.d(TAG, receiveData.toHex())
                }
                else
                    Log.d(TAG, "fail: ${receiveData.toHex()}")
            }
        } catch (e : Exception) {
            e.message?.let { Log.d(TAG, it) }
        }
        isoDep.close()
    }

    @ExperimentalStdlibApi
    fun fingerprintScan(command: String, isoDep : IsoDep) : STATUS {
        var state = STATUS.FAIL
        do {
            try {
                state = if (state == STATUS.PRESS || state == STATUS.RELEASE || state == STATUS.NONE) {
                    val curState =
                        getProcess(isoDep)
                    if (curState == STATUS.NONE)
                        state
                    else
                        curState
                } else {
                    getSelect(
                        activity!!,
                        command,
                        isoDep
                    )
                }
            } catch (e : Exception) {
                GlobalScope.launch(Dispatchers.Main) {
                    state = STATUS.FAIL
                    Toast.makeText(activity, "IO-Thread" + e.message, Toast.LENGTH_SHORT).show()
                }
            }
        } while (state != STATUS.SUCCESS && state != STATUS.FAIL)
        return state
    }
}