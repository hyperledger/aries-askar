require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

rnVersion = JSON.parse(File.read(File.join(__dir__, "node_modules" ,"react-native", "package.json")))["version"].split('.')[1]

folly_flags = '-DFOLLY_NO_CONFIG -DFOLLY_MOBILE=1 -DFOLLY_USE_LIBCPP=1 -DRNVERSION=' + rnVersion
folly_compiler_flags = folly_flags + ' ' + '-Wno-comma -Wno-shorten-64-to-32'
folly_version = '2020.01.13.00'

Pod::Spec.new do |s|
  s.name         = "react-native-aries-askar"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => "12.0" }
  s.source       = { :git => "https://github.com/animo/react-native-aries-askar.git", :tag => "#{s.version}" }

  s.xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++14",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_ROOT)/RCT-Folly\"",
    "OTHER_CFLAGS" => "$(inherited)" + " " + folly_flags,
  }

  s.pod_target_xcconfig = {
      "DEFINES_MODULE" => "YES",
      "USE_HEADERMAP" => "YES",
      "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/ReactCommon\" \"$(PODS_TARGET_SRCROOT)\" \"$(PODS_ROOT)/RCT-Folly\" \"$(PODS_ROOT)/Headers/Private/React-Core\" ",
  }

  s.source_files  = "ios/**/*.{h,m,mm}", "cpp/**/*.{h,cpp}"
  s.exclude_files = "cpp/tests/**/*"

  s.requires_arc = true

  s.ios.vendored_frameworks = "ios/Frameworks/AriesAskar.xcframework"

  s.dependency "React"
  s.dependency "React-Core"
  s.dependency "React-jsi"
  s.dependency "ReactCommon/turbomodule/core"
  s.dependency "React-callinvoker"
  s.dependency "RCT-Folly"
end
