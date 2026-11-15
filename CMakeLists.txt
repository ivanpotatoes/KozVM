cmake_minimum_required(VERSION 3.20)
project(KozVM VERSION 1.0.0 LANGUAGES CXX RC)
set(CMAKE_CXX_STANDARD 17)
set(X64DBG_SDK "" CACHE PATH "x64dbg plugin SDK")
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
 message(FATAL_ERROR "KozVM currently targets x64dbg only")
endif()
if(NOT EXISTS "${X64DBG_SDK}/_plugins.h")
 message(FATAL_ERROR "Set X64DBG_SDK")
endif()
add_library(KozVM SHARED src/plugin.cpp src/dialog.rc)
target_include_directories(KozVM PRIVATE "${X64DBG_SDK}")
target_include_directories(KozVM SYSTEM PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/unicorn/include")
target_compile_definitions(KozVM PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(KozVM PRIVATE /W4 /WX /EHsc /analyze)
target_link_libraries(KozVM PRIVATE "${X64DBG_SDK}/x64dbg.lib" "${X64DBG_SDK}/x64bridge.lib" comctl32)
set_target_properties(KozVM PROPERTIES SUFFIX .dp64 MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")


add_custom_command(TARGET KozVM POST_BUILD
 COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/runtime" "$<TARGET_FILE_DIR:KozVM>/KozVM"
 COMMENT "Copying isolated discovery runtime")

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/runtime/unicorn.dll")
 message(FATAL_ERROR "Run: python tools/fetch_unicorn.py")
endif()
