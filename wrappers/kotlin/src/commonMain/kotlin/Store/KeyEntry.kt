package askar.Store

import askar.crypto.Key
import askar.crypto.KeyEntryListHandle

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

//TODO: They localKey object is internal to askar and its props are not exposed to us. Not sure what the javascript wrapper is serializing
@Serializable
class KeyEntryObject(
    val algorithm: String,
    val name: String,
    val metadata: String?,
    val tags: Map<String, String>,
    @Transient
    val key: Key? = null
) {

    override fun toString(): String {
        return Json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        val o = other as KeyEntryObject
        return o.algorithm == this.algorithm && o.name == this.name && o.tags == this.tags && o.metadata == this.metadata
    }


}

class KeyEntry(
    private val list: KeyEntryListHandle,
    private val pos: Int
) {

    fun algorithm(): String {
        return list.getAlgorithm(pos)
    }

    fun name(): String {
        return list.getName(pos)
    }

    fun metadata(): String? {
        return list.getMetadata(pos)
    }

    fun tags(): Map<String, String> {
        return Json.decodeFromString<Map<String, String>>(list.getTags(pos) ?: "{}")
    }

    fun key(): Key {
        return Key(list.loadKey(pos))
    }

    fun toJson(): KeyEntryObject {
        val entry = KeyEntryObject(algorithm(), name(), metadata(), tags(), key())

        return entry
    }
}