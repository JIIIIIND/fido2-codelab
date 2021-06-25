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

package com.example.android.fido2.ui.home

import android.app.Activity
import android.app.Activity.RESULT_OK
import android.content.Intent
import android.content.IntentSender
import android.os.Bundle
import android.os.Debug
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Observer
import androidx.lifecycle.observe
import androidx.recyclerview.widget.LinearLayoutManager
import com.example.android.fido2.MainActivity
import com.example.android.fido2.R
import com.example.android.fido2.databinding.HomeFragmentBinding
import com.example.android.fido2.ui.observeOnce
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.fido.fido2.Fido2PendingIntent
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse

class HomeFragment : Fragment(), DeleteConfirmationFragment.Listener {

    companion object {
        private const val TAG = "HomeFragment"
        private const val FRAGMENT_DELETE_CONFIRMATION = "delete_confirmation"
        const val REQUEST_FIDO2_REGISTER = 1
    }

    private val viewModel: HomeViewModel by viewModels()
    private lateinit var binding: HomeFragmentBinding
    private lateinit var getResult: ActivityResultLauncher<IntentSenderRequest>

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        binding = HomeFragmentBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        getResult = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
            Log.d(TAG, "getResult")
            val errorExtra = result.data?.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA)
            when {
                errorExtra != null -> {
                    Log.d(TAG, "내 생각엔 이거 호출됨")
                    val error = AuthenticatorErrorResponse.deserializeFromBytes(errorExtra)
                    error.errorMessage?.let { errorMessage ->
                        Toast.makeText(requireContext(), errorMessage, Toast.LENGTH_LONG).show()
                        Log.e(TAG, errorMessage)
                    }
                }
                result.resultCode != Activity.RESULT_OK -> {
                    Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_SHORT).show()
                }
                result.data != null -> {
                    Log.d(TAG, "onActivityResult")
                    viewModel.registerResponse(result.data!!)
                }
            }
        }
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        val credentialAdapter = CredentialAdapter { credentialId ->
            DeleteConfirmationFragment.newInstance(credentialId)
                .show(childFragmentManager, FRAGMENT_DELETE_CONFIRMATION)
        }
        binding.credentials.run {
            layoutManager = LinearLayoutManager(view.context)
            adapter = credentialAdapter
        }
        viewModel.credentials.observe(viewLifecycleOwner, Observer { credentials ->
            credentialAdapter.submitList(credentials)
            binding.emptyCredentials.visibility = if (credentials.isEmpty()) {
                View.VISIBLE
            } else {
                View.INVISIBLE
            }
        })

        // Menu
        binding.appBar.replaceMenu(R.menu.home)
        binding.appBar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_reauth -> {
                    viewModel.reauth()
                    true
                }
                R.id.action_sign_out -> {
                    viewModel.signOut()
                    true
                }
                else -> false
            }
        }

        viewModel.processing.observe(viewLifecycleOwner, Observer {processing ->
            if (processing) {
                binding.processing.show()
            } else {
                binding.processing.hide()
            }
        })

        // FAB
        binding.add.setOnClickListener {
            viewModel.registerRequest().observeOnce(requireActivity()) {intent ->
                // TODO(2): Open the fingerprint dialog.
                // - Open the fingerprint dialog by launching the intent from FIDO2 API.
                Log.d(TAG, "fab click")
                try {
                    getResult.launch(IntentSenderRequest.Builder(intent).build())
                } catch (e: IntentSender.SendIntentException) {
                    Log.e(TAG, "Error launching pending intent for register request", e)
                }
            }
        }
    }

    override fun onDeleteConfirmed(credentialId: String) {
        viewModel.removeKey(credentialId)
    }

//    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
//        if (requestCode == REQUEST_FIDO2_REGISTER) {
//            val errorExtra = data?.getByteArrayExtra(Fido.FIDO2_KEY_ERROR_EXTRA)
//            when {
//                errorExtra != null -> {
//                    Log.d(TAG, "내 생각엔 이거 호출됨")
//                    val error = AuthenticatorErrorResponse.deserializeFromBytes(errorExtra)
//                    error.errorMessage?.let { errorMessage ->
//                        Toast.makeText(requireContext(), errorMessage, Toast.LENGTH_LONG).show()
//                        Log.e(TAG, errorMessage)
//                    }
//                }
//                resultCode != Activity.RESULT_OK -> {
//                    Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_SHORT).show()
//                }
//                data != null -> {
//                    Log.d(TAG, "onActivityResult")
//                    viewModel.registerResponse(data)
//                }
//            }
//        } else {
//            super.onActivityResult(requestCode, resultCode, data)
//        }
//    }
}
