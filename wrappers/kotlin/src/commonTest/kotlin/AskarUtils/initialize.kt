package tech.indicio.holdr.AskarUtils

import askar.Store.EntryObject
import askar.Store.KdfMethod
import askar.Store.Store
import askar.Store.StoreKeyMethod
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

fun getRawKey(): String? {
    return Store.generateRawKey("00000000000000000000000000000My1")
}

val firstEntry = EntryObject("category-one", "test-entry", tags =
buildJsonObject {
    put("~plaintag", "a")
    put("enctag", "b")
}, value = "foo"
)


val secondEntry = EntryObject("category-one", "secondEntry", tags =
buildJsonObject {
    put("~plaintag", "a")
    put("enctag", "b")
}, value = buildJsonObject {
    put("foo", "bar")
})


//     const thirdEntry = {
//        category: 'category-one',
//        name: 'thirdEntry',
//        value: { foo: 'baz' },
//        tags: { '~plaintag': 'a', enctag: 'b' },
//    }


const val testStoreUri = "sqlite://local.db"

suspend fun setupWallet(): Store {
    val key = getRawKey() ?: throw Error("Key came back as null")
    return Store.provision(
        recreate = true,
        uri = testStoreUri,
        keyMethod = StoreKeyMethod(KdfMethod.Raw),
        passkey = key
    )
}

