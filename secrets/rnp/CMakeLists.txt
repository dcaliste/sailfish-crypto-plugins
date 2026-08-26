set(SRC
	plugin.cpp
	rnpkeys.cpp
	rnpffi.cpp
        ${PROJECT_SOURCE_DIR}/rnp/rnp.cpp)
set(HEADERS
	rnpkeys.h
	rnpffi.h
        ${PROJECT_SOURCE_DIR}/rnp/rnp_p.h)

add_library(sailfishcrypto-rnp SHARED ${SRC} ${HEADERS})

target_include_directories(sailfishcrypto-rnp PRIVATE ${PROJECT_SOURCE_DIR}/rnp)
target_link_libraries(sailfishcrypto-rnp
		PRIVATE
	Qt5::Core
	PkgConfig::SECRETS
        PkgConfig::RNP)

# Install the library
install(TARGETS sailfishcrypto-rnp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/Sailfish/Crypto/)
