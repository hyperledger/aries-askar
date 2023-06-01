package askar.crypto

import askar.Askar

class CryptoBox {

    companion object {
        fun randomNonce(): String {
            return Askar.cryptoBox.keyCryptoBoxRandomNonce()
        }

        fun cryptoBox(recipientKey: Key, senderKey: Key, message: String, nonce: String): String {
            return Askar.cryptoBox.keyCryptoBox(recipientKey.handle(), senderKey.handle(), message, nonce)
        }

        fun open(recipientKey: Key, senderKey: Key, message: String, nonce: String): String {
            return Askar.cryptoBox.cryptoBoxOpen(recipientKey.handle(), senderKey.handle(), message, nonce)
        }

        fun seal(recipientKey: Key, message: String): ByteArray {
            return Askar.cryptoBox.cryptoBoxSeal(recipientKey.handle(), message)
        }

        fun sealOpen(recipientKey: Key, cipherText: ByteArray): String {
            return Askar.cryptoBox.cryptoBoxSealOpen(recipientKey.handle(), cipherText)
        }

    }
}