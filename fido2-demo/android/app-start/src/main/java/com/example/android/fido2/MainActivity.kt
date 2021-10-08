/*
 * Copyright 2019 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.fido2

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.Observer
import com.example.android.fido2.repository.SignInState
import com.example.android.fido2.ui.auth.AuthFragment
import com.example.android.fido2.ui.home.HomeFragment
import com.example.android.fido2.ui.observeOnce
import com.example.android.fido2.ui.username.UsernameFragment
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kr.co.sisoul.sisoultaginfo.fingerPrint.STATUS

private val TAG = "MainActivityTAG"

class MainActivity : AppCompatActivity() {

    private lateinit var nfcHandler : NFCHandler
    private val viewModel: MainViewModel by viewModels()
    var tag : Tag? = null

    @ExperimentalStdlibApi
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        setSupportActionBar(findViewById(R.id.toolbar))

        viewModel.signInState.observe(this, Observer { state ->
            when (state) {
                is SignInState.SignedOut -> {
                    showFragment(UsernameFragment::class.java) { UsernameFragment() }
                }
                is SignInState.SigningIn -> {
                    showFragment(AuthFragment::class.java) { AuthFragment() }
                }
                is SignInState.SignInError -> {
                    Toast.makeText(this, state.error, Toast.LENGTH_LONG).show()
                    // return to username prompt
                    showFragment(UsernameFragment::class.java) { UsernameFragment() }
                }
                is SignInState.SignedIn -> {
                    Log.d(TAG, "signed in: ${viewModel.bioResult}")
                    if (viewModel.bioResult() == BiometricManager.BIOMETRIC_SUCCESS) {
                        Toast.makeText(this, "state signedin success: ${viewModel.bioResult()}", Toast.LENGTH_SHORT).show()
                        showFragment(HomeFragment::class.java) { HomeFragment() }
                    }
                    else {
//                        launchNFC()
                    }
                }
            }
        })
        nfcHandler = NFCHandler(this)
    }

    @ExperimentalStdlibApi
    fun launchNFC() {
        this.nfcHandler.activateNfcController()
        val nfcResult = MutableLiveData<STATUS>()
        nfcResult.observeOnce(this) {
            if (it == STATUS.SUCCESS) {
                Toast.makeText(this, "nfc 인증 성공", Toast.LENGTH_SHORT).show()
                this.nfcHandler.deActivateNfcAdapter()
                showFragment(HomeFragment::class.java) { HomeFragment() }
            } else {
                Toast.makeText(this, "nfc 인증 오류", Toast.LENGTH_SHORT).show()
            }
        }
        GlobalScope.launch(Dispatchers.IO) {
            if (tag != null)
                nfcResult.postValue(fingerprintAction())
        }
    }

    @ExperimentalStdlibApi
    private suspend fun fingerprintAction() : STATUS {
        var nfcResult = STATUS.FAIL
        withContext(Dispatchers.IO) {
            try {
                IsoDep.get(tag)?.use { isoDep ->
                     nfcResult = nfcHandler.fingerprintScan("IDENTIFY", isoDep)
                }
            } catch (e : Exception) {
                GlobalScope.launch(Dispatchers.Main) {
					Toast.makeText(this@MainActivity, e.message, Toast.LENGTH_SHORT).show()
                }
            }
        }
        return nfcResult
    }

//    @ExperimentalStdlibApi
    override fun onResume() {
        super.onResume()
        Log.d(TAG, "onResume")
        viewModel.setFido2ApiClient(Fido.getFido2ApiClient(this))
//        if (viewModel.signInState.value is SignInState.SignedIn)
//            launchNFC()
    }

//    @ExperimentalStdlibApi
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        Log.d(TAG, "onNewIntent")
//        tag = this.nfcHandler.getTag(intent) ?: return
    }

    override fun onPause() {
        super.onPause()
        Log.d(TAG, "onPause")
        viewModel.setFido2ApiClient(null)
    }

    private fun showFragment(clazz: Class<out Fragment>, create: () -> Fragment) {
        val manager = supportFragmentManager
        if (!clazz.isInstance(manager.findFragmentById(R.id.container))) {
            manager.commit {
                replace(R.id.container, create())
            }
        }
    }

}
