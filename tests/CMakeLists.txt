find_package(Qt5 ${QT_MIN_VERSION} COMPONENTS Test REQUIRED)

set(PLUGIN_SRC
	${PROJECT_SOURCE_DIR}/secrets/rnp/rnpkeys.cpp
	${PROJECT_SOURCE_DIR}/secrets/rnp/rnpffi.cpp
	${PROJECT_SOURCE_DIR}/rnp/rnp.cpp)

# The plugin under its test name.
add_library(sailfishcrypto-rnp-test SHARED
	${PROJECT_SOURCE_DIR}/secrets/rnp/plugin.cpp
	${PLUGIN_SRC})
target_compile_definitions(sailfishcrypto-rnp-test PRIVATE SAILFISHCRYPTO_TESTPLUGIN)
target_include_directories(sailfishcrypto-rnp-test PRIVATE
	${PROJECT_SOURCE_DIR}/rnp
	${PROJECT_SOURCE_DIR}/secrets/rnp)
target_link_libraries(sailfishcrypto-rnp-test
		PRIVATE
	Qt5::Core
	PkgConfig::SECRETS
	PkgConfig::RNP)

add_executable(tst_rnp tst_rnp.cpp ${PLUGIN_SRC})
target_include_directories(tst_rnp PRIVATE
	${PROJECT_SOURCE_DIR}/rnp
	${PROJECT_SOURCE_DIR}/secrets/rnp)
target_link_libraries(tst_rnp
		PRIVATE
	Qt5::Test
	PkgConfig::SECRETS
	PkgConfig::RNP)
add_test(NAME tst_rnp COMMAND ${CMAKE_COMMAND} -E env
	RNP_TEST_PLUGIN=$<TARGET_FILE:sailfishcrypto-rnp-test>
	$<TARGET_FILE:tst_rnp>)
