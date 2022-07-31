cmake_minimum_required(VERSION 3.9.0)
project(ariesaskarreactnative)

set (PACKAGE_NAME "ariesaskarreactnative")
set (LIB_NAME "ariesaskar")
set (BUILD_DIR ${CMAKE_SOURCE_DIR}/build)

file (GLOB LIBFBJNI_INCLUDE_DIR "${BUILD_DIR}/fbjni-*-headers.jar/")
file (GLOB LIBRN_DIR "${BUILD_DIR}/react-native-0*/jni/${ANDROID_ABI}")
file (GLOB LIBASKAR_DIR "${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}")

include_directories(
  ../cpp
  ../cpp/include
  "${LIBASKAR_DIR}"
  "${LIBFBJNI_INCLUDE_DIR}"
  "${NODE_MODULES_DIR}/react-native/React"
  "${NODE_MODULES_DIR}/react-native/React/Base"
  "${NODE_MODULES_DIR}/react-native/ReactCommon"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/callinvoker"
  "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/jni"
  "${NODE_MODULES_DIR}/react-native/ReactAndroid/src/main/java/com/facebook/react/turbomodule/core/jni"
)

add_library(
  ${PACKAGE_NAME}
  SHARED
  cpp-adapter.cpp
  ../cpp/HostObject.cpp
  ../cpp/turboModuleUtility.cpp
  ../cpp/ariesAskar.cpp
)

set_target_properties(
  ${PACKAGE_NAME}
  PROPERTIES
  CXX_STANDARD 17
  CXX_EXTENSION OFF
  POSITION_INDEPENDENT_CODE ON
)

find_library(
  LOG_LIB
  log
)

# test
find_library(
  FBJNI_LIB
  fbjni
  PATHS ${LIBRN_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

find_library(
  REACT_NATIVE_JNI_LIB
  reactnativejni
  PATHS ${LIBRN_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

find_library(
  JSI_LIB
  jsi
  PATHS ${LIBRN_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

find_library(
  ASKAR_LIB 
  aries_askar 
  paths ${LIBASKAR_DIR}
  NO_CMAKE_FIND_ROOT_PATH
)

if (NOT ASKAR_LIB)
  message(FATAL_ERROR "Could not find ASKAR_LIB at: ${LIBASKAR_DIR}")
endif()

target_link_libraries(
  ${PACKAGE_NAME}
  ${ASKAR_LIB}
  ${LOG_LIB} 
  ${JSI_LIB}
  ${REACT_NATIVE_JNI_LIB}
  ${FBJNI_LIB}
  android
)
