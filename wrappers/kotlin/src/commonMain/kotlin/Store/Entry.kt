package askar.Store

import askar.crypto.EntryListHandle
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable
class EntryObject(val category: String, val name: String,val value: String, val tags: Map<String, String>) {

    override fun toString(): String {
        return Json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        if(other == null) return false
        val o = other as EntryObject
        return o.category == this.category && o.name == this.name && o.value == this.value && o.tags == this.tags
    }

}
class Entry (private val list: EntryListHandle, private val pos: Int) {

    fun category(): String {
        return this.list.getCategory(this.pos)
    }

    fun name(): String {
        return this.list.getName(this.pos)
    }

    fun value(): String {
        return this.list.getValue(this.pos)
    }

    //Revisit if needed later
//    private fun rawValue(): String {
//        return this.list.getValue(this.pos)
//    }

    fun tags(): Map<String, String> {
        return Json.decodeFromString<Map<String, String>>(list.getTags(pos) ?: "{}")
    }

    fun toJson(): EntryObject {
        val entry = EntryObject(category(), name(), tags = tags(), value = value())
       return entry
    }

}