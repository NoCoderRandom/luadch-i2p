# Build the hub executable (luadch / Luadch.exe).
#
# It is a thin C launcher that embeds the Lua interpreter and runs
# core/init.lua from the install root.

add_executable(luadch hub.c)
target_link_libraries(luadch PRIVATE lua)

# On Linux/BSD, link against libm + libdl for math + dlopen() (used by the
# Lua require() loader for the C modules). $<...> generators handle the
# Windows case automatically (no equivalents needed; lua.dll re-exports them).
if(UNIX)
    target_link_libraries(luadch PRIVATE m ${CMAKE_DL_LIBS})

    find_package(Threads REQUIRED)

    add_library(luadch_i2p_forwarder STATIC
        i2p_forwarder.cpp
    )
    target_compile_features(luadch_i2p_forwarder PUBLIC cxx_std_20)
    target_include_directories(luadch_i2p_forwarder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(luadch_i2p_forwarder PUBLIC OpenSSL::Crypto Threads::Threads)

    add_executable(luadch-i2p-forward i2p_forward_main.cpp)
    target_compile_features(luadch-i2p-forward PRIVATE cxx_std_20)
    target_link_libraries(luadch-i2p-forward PRIVATE luadch_i2p_forwarder)
endif()

# Windows: name the binary Luadch.exe (capitalised) and embed the icon.
if(WIN32)
    set_target_properties(luadch PROPERTIES OUTPUT_NAME "Luadch")

    # Icon resource — windres compiles res.rc → object file
    enable_language(RC)
    target_sources(luadch PRIVATE ${CMAKE_SOURCE_DIR}/res/res.rc)
endif()

install(TARGETS luadch RUNTIME DESTINATION .)
if(UNIX)
    install(TARGETS luadch-i2p-forward RUNTIME DESTINATION .)
endif()
