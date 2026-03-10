package com.oniimediaworks.meshinfinity

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object KeystoreBridge {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "mesh-infinity-identity-key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val TAG_LENGTH_BITS = 128

    @JvmStatic
    fun wrapKey(input: ByteArray): ByteArray {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(input)
        val buffer = ByteBuffer.allocate(4 + iv.size + ciphertext.size)
        buffer.putInt(iv.size)
        buffer.put(iv)
        buffer.put(ciphertext)
        return buffer.array()
    }

    @JvmStatic
    fun unwrapKey(input: ByteArray): ByteArray {
        val key = getExistingKey() ?: throw IllegalStateException("Keystore key missing")
        val buffer = ByteBuffer.wrap(input)
        val ivLength = buffer.int
        require(ivLength in 1..32) { "Invalid IV length" }
        val iv = ByteArray(ivLength)
        buffer.get(iv)
        val ciphertext = ByteArray(buffer.remaining())
        buffer.get(ciphertext)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    @JvmStatic
    fun deleteKey(): Boolean {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keystore.load(null)
        if (keystore.containsAlias(KEY_ALIAS)) {
            keystore.deleteEntry(KEY_ALIAS)
        }
        return true
    }

    private fun getOrCreateKey(): SecretKey {
        val existing = getExistingKey()
        if (existing != null) return existing

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    private fun getExistingKey(): SecretKey? {
        val keystore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keystore.load(null)
        val entry = keystore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
        return entry?.secretKey
    }
}
