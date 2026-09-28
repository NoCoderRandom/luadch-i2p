if(UNIX)
    add_executable(luadch-i2p-forwarder-tests
        ForwarderTest.cpp
    )
    target_link_libraries(luadch-i2p-forwarder-tests PRIVATE luadch_i2p_forwarder)

    add_test(NAME luadch-i2p-forwarder-tests COMMAND luadch-i2p-forwarder-tests)
    set_tests_properties(luadch-i2p-forwarder-tests PROPERTIES TIMEOUT 20)
endif()
