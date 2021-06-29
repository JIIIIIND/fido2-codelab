package kr.co.sisoul.sisoultaginfo.fingerPrint

import android.app.Activity
import android.nfc.tech.IsoDep
import android.util.Log

private val TAG = "NFC_COMMAND"

@ExperimentalStdlibApi
fun getSelect(activity : Activity, command : String, isoDep: IsoDep) : STATUS {
	val select = arrayOf(
		0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0xAA, 0x55, 0x00, 0x01, 0x00, 0x02
	)
	//[0, 0xa4, 0x04, 0x00, 0x07, 0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
	var result = STATUS.FAIL
	if (!isoDep.isConnected)
		isoDep.connect()
	try {
		isoDep.use {tech ->
			val receiveData = isoDep.transceive(ByteArray(select.size) { i -> select[i].toByte()})
			Log.d(TAG, "SELECT:${toHexString(receiveData)}")
			if (receiveData.size >= 2 &&
				receiveData[receiveData.size - 2] == 0x90.toByte() &&
				receiveData[receiveData.size - 1] == 0x00.toByte()) {
				result = when (command) {
					"ENROLL" -> getEnroll(
						activity,
						tech
					)
					"IDENTIFY" -> getIdentify(
						tech
					)
					"DELETE" -> getDelete(
						activity,
						tech
					)
					else -> {
//						Log.d(TAG, "undefined Command")
						STATUS.FAIL
					}
				}
			}
		}
	} catch (e : Exception) {
//		e.message?.let { Log.d(TAG, it) }
	}
	isoDep.close()
	return result
}

@ExperimentalStdlibApi
private fun getIdentify(isoDep: IsoDep) : STATUS {
	val identify = arrayOf(
		0x00, 0xA1, 0x00, 0x00, 0x00
	)
	// 지문 인식으로 등록된 유저인지 확인 함수임
	var result = STATUS.FAIL
	try {
		if (!isoDep.isConnected)
			isoDep.connect()
		isoDep.use {tech ->
			val receiveData = tech.transceive(ByteArray(identify.size) { i -> identify[i].toByte()})
			Log.d(TAG, toHexString(receiveData))
			if (receiveData.size >= 2 &&
				receiveData[receiveData.size - 2] == 0x90.toByte() &&
				receiveData[receiveData.size - 1] == 0x00.toByte()) {
				//전송이 성공 했으므로 getProcess를 통해 결과 출력 필요
				result = getProcess(tech)
			}
		}
	} catch (e : Exception) {
//		e.message?.let { Log.d(TAG, it) }
		Log.d(TAG, "getIdentify catch")
		return STATUS.FAIL
	}
	return result
}

@ExperimentalStdlibApi
private fun getDelete(activity : Activity, isoDep: IsoDep) : STATUS {
	val delete = arrayOf(
		0x00, 0xAD, 0x00, 0x00, 0x00
	)
	var result = STATUS.SUCCESS
	try {
		if (!isoDep.isConnected)
			isoDep.connect()
		isoDep.use {tech ->
			if (result == STATUS.SUCCESS) {
				val receiveData = tech.transceive(ByteArray(delete.size) { i -> delete[i].toByte()})
				Log.d(TAG, toHexString(receiveData))
				if (receiveData.size >= 2 &&
					receiveData[receiveData.size - 2] == 0x90.toByte() &&
					receiveData[receiveData.size - 1] == 0x00.toByte()) {
					result =
						getProcess(tech)
				}
			}
			return result
		}
	} catch (e : Exception) {
//		Toast.makeText(activity, e.message, Toast.LENGTH_SHORT).show()
		return STATUS.FAIL
	}
}

@ExperimentalStdlibApi
private fun getEnroll(activity : Activity, isoDep: IsoDep) : STATUS {
	val enroll = arrayOf(
		0x00, 0xA0, 0x00, 0x00, 0x00
	)
	var result : STATUS =
		STATUS.FAIL
	try {
		if (!isoDep.isConnected)
			isoDep.connect()
		isoDep.use {tech ->
			val receiveData = tech.transceive(ByteArray(enroll.size) { i -> enroll[i].toByte()})
			Log.d(TAG, "ENROLL:${toHexString(receiveData)}")
			if (receiveData.size >= 2 &&
				receiveData[receiveData.size - 2] == 0x90.toByte() &&
				receiveData[receiveData.size - 1] == 0x00.toByte()) {
				result = getProcess(tech)
			}
		}
	} catch (e : Exception) {
//		Toast.makeText(activity, e.message, Toast.LENGTH_SHORT).show()
		return STATUS.FAIL
	}
	return result
}

@ExperimentalStdlibApi
fun toHexString(b: ByteArray?) : String {
	var result = ""
	val charSet = "0123456789ABCDEF"

	if (b != null) {
		for (value in b) {
			result += charSet[((value.toULong().rotateRight(4)) and 15u).toInt()]
			result += charSet[(value.toULong() and 15u).toInt()]
		}
	}
	return result
}

enum class STATUS {
	SUCCESS, FAIL, RELEASE, PRESS, FULL, EMPTY, NONE
}

@ExperimentalStdlibApi
fun getProcess(isoDep: IsoDep) : STATUS {
	val process = arrayOf(
		0x00, 0xB0, 0x00, 0x00, 0x03
	)
	try {
		if (!isoDep.isConnected)
			isoDep.connect()
		isoDep.use {tech ->
			val receiveData = tech.transceive(ByteArray(process.size) { i -> process[i].toByte()})
			Log.d(TAG, toHexString(receiveData))
			if (receiveData.size >= 2 &&
				receiveData[receiveData.size - 2] == 0x90.toByte() &&
				receiveData[receiveData.size - 1] == 0x00.toByte()) {
				return when (receiveData[0].toInt()) {
					0 -> STATUS.SUCCESS
					-1 -> STATUS.FAIL
					-2 -> when {
						receiveData[2] == 2.toByte() -> STATUS.PRESS
						receiveData[2] == 3.toByte() -> STATUS.RELEASE
						else -> STATUS.NONE
					}
					-3 -> STATUS.FULL
					-4 -> STATUS.EMPTY
					else -> STATUS.FAIL
				}
			}
		}
	} catch (e : Exception) {
		Log.d(TAG, "getProcess catch")
//		e.message?.let { Log.d(TAG, it) }
	}
	return STATUS.FAIL
}