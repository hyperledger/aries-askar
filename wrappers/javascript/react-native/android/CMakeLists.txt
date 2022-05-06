cmake_minimum_required(VERSION 3.9.0)

set (PACKAGE_NAME "ariesaskarreactnative")
set (LIB_NAME "ariesaskar")
set (BUILD_DIR ${CMAKE_SOURCE_DIR}/build)

include_directories(
  ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}
  ../cpp
  ../cpp/include
  "${NODE_MODULES_DIR}/react-native/React"
  "${NODE_MODULES_DIR}/react-native/React/Base"
  "${NODE_MODULES_DIR}/react-native/ReactCommon/jsi"
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

file (GLOB LIBRN_DIR  "${PREBUILT_DIR}/${ANDROID_ABI}")
file (GLOB LIBASKAR_DIR "${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}")

find_library(
  LOG_LIB
  log
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
  android
)
