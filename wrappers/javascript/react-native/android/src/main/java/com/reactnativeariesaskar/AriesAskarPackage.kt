package com.reactnativeariesaskar

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class AriesAskarPackage: ReactPackage {
  override fun createNativeModules(reactContext: ReactApplicationContext)
    = listOf(AriesAskarModule(reactContext))

  override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>>
    = emptyList()
}
