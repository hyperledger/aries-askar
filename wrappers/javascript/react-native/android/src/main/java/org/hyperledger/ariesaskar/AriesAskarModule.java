package org.hyperledger.ariesaskar;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.facebook.react.bridge.JavaScriptContextHolder;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.module.annotations.ReactModule;

@ReactModule(name = AriesAskarModule.NAME)
public class AriesAskarModule extends ReactContextBaseJavaModule {
    public static final String NAME = "AriesAskar";

    public AriesAskarModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    @NonNull
    public String getName() {
        return NAME;
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    public boolean install() {
      try {
        Log.i(NAME, "Loading C++ library...");
        System.loadLibrary("ariesaskarreactnative");

        JavaScriptContextHolder jsContext = getReactApplicationContext().getJavaScriptContextHolder();
        nativeInstall(jsContext.get());
        return true;
      } catch (Exception exception) {
        Log.e(NAME, "Failed to install JSI Bindings!", exception);
        return false;
      }
    }

    private static native void nativeInstall(long jsiPtr);
}
