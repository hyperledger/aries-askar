package com.reactnativeariesaskar

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.module.annotations.ReactModule

@ReactModule(name = AriesAskarModule.NAME)
class AriesAskarModule(reactContext: ReactApplicationContext?) : ReactContextBaseJavaModule(reactContext) {
  companion object {
    const val NAME = "AriesAskar"

    init {
      try {
        System.loadLibrary("aries_askar")
      } catch (ignored: Exception) {
      }
    }
  }

  private val nativeProxy = NativeProxy()

  override fun getName() = NAME

  override fun initialize() {
    super.initialize()
    nativeProxy.installJsi(this.reactApplicationContext)
  }
}
