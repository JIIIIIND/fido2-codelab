package com.example.android.fido2

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
import kr.co.sisoul.sisoultaginfo.fingerPrint.STATUS
import kr.co.sisoul.sisoultaginfo.fingerPrint.getProcess
import kr.co.sisoul.sisoultaginfo.fingerPrint.getSelect
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