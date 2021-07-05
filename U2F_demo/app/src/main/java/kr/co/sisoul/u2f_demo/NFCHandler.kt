package kr.co.sisoul.u2f_demo

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.*
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kr.co.sisoul.sisoultaginfo.fingerPrint.*
import java.io.ByteArrayInputStream
import java.lang.UnsupportedOperationException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.security.cert.X509Certificate
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

    fun ByteArray.toHex(): String = joinToString("", "", "") { eachByte ->
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

    private val SELECTU2F = byteArrayOf(
        0x00.toByte(), 0xA4.toByte(), 0x04.toByte(), 0x00.toByte(), 0x08.toByte(), 0xA0.toByte(), 0x00.toByte(), 0x00.toByte(),
        0x06.toByte(), 0x47.toByte(), 0x2F.toByte(), 0x00.toByte(), 0x01.toByte()
    )

    private val GETRESPONSE = byteArrayOf(
        0x00.toByte(), 0xC0.toByte(), 0x00.toByte(), 0x00.toByte()
    )

    fun u2fSelect(isoDep: IsoDep, command: String) {
        var result = STATUS.FAIL
        try {
            if (!isoDep.isConnected)
                isoDep.connect()
            isoDep.use {tech ->
                var receiveData = isoDep.transceive(SELECTU2F)
                if (receiveData.size >= 2 &&
                        receiveData[receiveData.size - 2] == 0x90.toByte() &&
                        receiveData[receiveData.size - 1] == 0x00.toByte()) {
                    Log.d(TAG, "SELECT OK")
                    when (command) {
                        "REGISTER" -> u2fRegister(isoDep)
                        "AUTHENTICATE" -> u2fAuthenticate(isoDep)
                        else -> Log.d(TAG, "command not found")
                    }
                }
                else
                    Log.d(TAG, "fail: ${receiveData.toHex()}")
            }
        } catch (e : Exception) {
            e.message?.let { Log.d(TAG, "select $it") }
        }
        isoDep.close()
    }

    private fun u2fSendCmd(isoDep: IsoDep, apdu: ByteArray) : ByteArray {
        var cmd = apdu
        var status = 0x6100
        var data = ByteArray(0)

        while ((status.and(0xff00) == 0x6100)) {
            val receiveData = isoDep.transceive(cmd)
            Log.d(TAG, "6100 result: ${receiveData.toHex()}")
            status = ((0xff.and(receiveData[receiveData.size - 2].toInt()).shl(8))
                    .or(0xff.and(receiveData[receiveData.size - 1].toInt())))
            data += receiveData.slice(0 until (receiveData.size - 2))
            cmd = GETRESPONSE + receiveData[receiveData.size - 1]
            Log.d(TAG, "${cmd.toHex()}")
        }
        if (status == 0x9000) {
            Log.d(TAG, data.toHex())
        }
        else
            throw Exception("apdu error")
        return data
    }

    lateinit var pubKey : ByteArray
    lateinit var keyHandle : ByteArray
    lateinit var cert: ByteArray
    lateinit var sign: ByteArray
    lateinit var signature: Signature

    private fun parse_tlv_size(tlv: ByteArray) : Int {
        var l : Int = tlv[1].toInt()
        var nBytes = 1
        if (l > 0x80.toByte()) {
            nBytes = l - 0x80.toByte()
            l = 0
            for (i in (2 until (2 + nBytes))) {
                l = (l * 256 + tlv[i])
            }
        }
        return 2 + nBytes + l
    }

    fun String.decodeHex(): ByteArray {
        require(length % 2 == 0) { "Not even length" }
        return chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
    }

    private val CERTSTOFIX : Array<ByteArray>  = arrayOf(
            "349bca1031f8c82c4ceca38b9cebf1a69df9fb3b94eed99eb3fb9aa3822d26e8".decodeHex(),
            "dd574527df608e47ae45fbba75a2afdd5c20fd94a02419381813cd55a2a3398f".decodeHex(),
            "1d8764f0f7cd1352df6150045c8f638e517270e8b5dda1c63ade9c2280240cae".decodeHex(),
            "d0edc9a91a1677435a953390865d208c55b3183c6759c9b5a7ff494c322558eb".decodeHex(),
            "6073c436dcd064a48127ddbf6032ac1a66fd59a0c24434f070d4e564c124c897".decodeHex(),
            "ca993121846c464d666096d35f13bf44c1b05af205f9b4a1e00cf6cc10c5e511".decodeHex()
    )

    private fun fixCert(der: ByteArray) : ByteArray {
        var returnValue = der
        var md = MessageDigest.getInstance("SHA-256")
        md.update(der)
        val finalHash = md.digest()
        Log.d(TAG, "HASH: ${finalHash.toHex()}")
        if (finalHash in CERTSTOFIX) {
            returnValue = returnValue.sliceArray(
                    0 until (returnValue.size - 257)) +
                            0x00.toByte() +
                            returnValue.sliceArray((returnValue.size - 256) until returnValue.size)
        }
        return returnValue
    }

    private fun reverseBit(crc: Int) :Int {
        var value = crc
        value = (value.and(0xaaaa).shr(1)).or(value.and(0x5555).shl(1))
        value = (value.and(0xcccc).shr(2)).or(value.and(0x3333).shl(2))
        value = (value.and(0xf0f0).shr(4)).or(value.and(0x0f0f).shl(4))
        value = (value.and(0xff00).shr(8)).or(value.and(0x00ff).shl(8))
        return value
    }

    private fun intToByteArray(value : Int, order: ByteOrder) : ByteArray {
        val bufferSize = Int.SIZE_BYTES
        val buffer = ByteBuffer.allocate(bufferSize)
        buffer.order(order)
        buffer.putInt(value)
        return buffer.array()
    }

    private fun u2fRegister(isoDep: IsoDep) {
        val challenge = getSHA256("test")
        val appParam = getSHA256("http://sisoul.co.kr")
        val apdu = ByteArray(69)
        ByteArray(0)
        apdu[1] = 0x01.toByte()
        apdu[2] = 0x03.toByte()
        apdu[4] = 0x40.toByte()
        challenge.copyInto(apdu, 5, 0)
        appParam.copyInto(apdu, 5 + 32, 0)

        Log.d(TAG, "challenge: ${challenge.toHex()}")
        Log.d(TAG, "appParam: ${appParam.toHex()}")
        Log.d(TAG, "apdu: ${apdu.toHex()}")

        if (!isoDep.isConnected)
            isoDep.connect()
        try {
            isoDep.use {tech ->
                var r = u2fSendCmd(isoDep, apdu)
                if (r[0] != 0x05.toByte()) {
                    throw Exception("not 0x05")
                }
                r = r.sliceArray(1 until r.size)    // r.pop(0) != 0x05 부분
                pubKey = r.sliceArray(0 until 65)
                r = r.sliceArray(65 until r.size)   // pub_key = pop_bytes(r, 65)
                val keyLen = r[0]
                r = r.sliceArray(1 until r.size) // key_handle의 r.pop(0)
                keyHandle = r.sliceArray(0 until keyLen)
                r = r.sliceArray(keyLen until r.size)   // key_handle = pop_bytes(r, r.pop(0))
                val certLen = parse_tlv_size(r)
                cert = fixCert(r.sliceArray(0 until (certLen)))
                Log.d(TAG, "${cert.toHex()}")
                r = r.sliceArray(certLen until r.size)
                sign = r
                try {
                    Log.d(TAG, "${cert.toHex()}")
                    val cf = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(cert))
                    val publicKey = cf.publicKey
                    cf.verify(publicKey)
                    GlobalScope.launch(Dispatchers.Main) {
                        Toast.makeText(activity, "Register Success", Toast.LENGTH_SHORT).show()
                    }
                }   catch (e : NoSuchAlgorithmException) {
                    e.message?.let { Log.d(TAG, "ERROR NOSUCHALGO: $it") }
                } catch (e : InvalidKeyException) {
                    e.message?.let { Log.d(TAG, "ERROR InvalidKey: $it") }
                } catch (e : SignatureException) {
                    e.message?.let { Log.d(TAG, "ERROR Signature: $it") }
                } catch (e : CertificateException) {
                    e.message?.let { Log.d(TAG, "ERROR Certificate: $it") }
                } catch (e : UnsupportedOperationException) {
                    e.message?.let { Log.d(TAG, "ERROR UnsupportedOeration: $it") }
                }
            }
        } catch(e: Exception) {
            e.message?.let { Log.d(TAG, "ERROR: $it") }
        }
        isoDep.close()
    }

    private val AUTHENTICATE = byteArrayOf(
        0x00.toByte(), 0x02.toByte(), 0x03.toByte(), 0x00.toByte()
    )

    fun ByteArray.toInt() : Int {
        var result = this[3].toInt() and 0xFF
        result = result or (this[2].toInt() shl 8 and 0xFF00)
        result = result or (this[1].toInt() shl 16 and 0xFF0000)
        result = result or (this[0].toInt() shl 24)
        return result
    }

    private val PUBKEYPREFIX = byteArrayOf(
            0x30.toByte(), 0x59.toByte(), 0x30.toByte(), 0x13.toByte(), 0x06.toByte(), 0x07.toByte(), 0x2a.toByte(), 0x86.toByte(),
            0x48.toByte(), 0xce.toByte(), 0x3d.toByte(), 0x02.toByte(), 0x01.toByte(), 0x06.toByte(), 0x08.toByte(), 0x2a.toByte(),
            0x86.toByte(), 0x48.toByte(), 0xce.toByte(), 0x3d.toByte(), 0x03.toByte(), 0x01.toByte(), 0x07.toByte(), 0x03.toByte(),
            0x42.toByte(), 0x00.toByte()
    )

    private fun u2fAuthenticate(isoDep: IsoDep) {
        val challenge = getSHA256("test")
        val appParam = getSHA256("http://sisoul.co.kr")
        val request = challenge + appParam + keyHandle.size.toByte() + keyHandle
        if (!isoDep.isConnected)
            isoDep.connect()
        try {
            isoDep.use {tech ->
                var response = u2fSendCmd(isoDep, AUTHENTICATE + request.size.toByte() + request)
                var buf = response.sliceArray(0 until (response.size - 2))
                val userPresence = response[0]
                response = response.sliceArray(1 until response.size)
                val count = response.sliceArray(0 until 4).toInt()
                response = response.sliceArray(4 until response.size)
                val localSign = buf
                val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(PUBKEYPREFIX + pubKey))
                Log.d(TAG, "publicKey making success")
                try {
                    val signature = Signature.getInstance("SHA256withECDSA")
                    Log.d(TAG, "signature getInstance")
                    signature.initVerify(publicKey)
                    Log.d(TAG, "signature init Verify")
                    signature.verify(localSign)
                    GlobalScope.launch(Dispatchers.Main) {
                        Toast.makeText(activity, "Authenticate Success", Toast.LENGTH_SHORT).show()
                    }
                } catch(e: Exception) {
                    GlobalScope.launch(Dispatchers.Main) {
                        e.message?.let { Log.d(TAG, "authenticate error: $it") }
                        Toast.makeText(activity, "Authenticate Error ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        } catch (e: Exception) {
            e.message?.let { Log.d(TAG, it)}
        }
    }

    private val GETSERIAL = byteArrayOf(
            0x00.toByte(), 0x50.toByte(), 0x00.toByte(), 0x00.toByte(), 0x15.toByte()
    )

    private fun u2fGetSerial(isoDep: IsoDep) : ByteArray {
        if (!isoDep.isConnected)
            isoDep.connect()
        try {
            isoDep.use {tech ->
                val response = isoDep.transceive(GETSERIAL)
                if (response.size >= 2 &&
                        response[response.size - 2] == 0x90.toByte() &&
                        response[response.size - 1] == 0x00.toByte()) {
                    return response.sliceArray(0 until (response.size - 2))
                }
            }
        } catch (e: Exception) {
            e.message?.let { Log.d(TAG, it) }
        }
        return ByteArray(0)
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