set(SRC
  plugin.cpp
  ${PROJECT_SOURCE_DIR}/rnp/rnp.cpp)
set(HEADERS
  plugin.h
  ${PROJECT_SOURCE_DIR}/rnp/rnp_p.h)

add_library(rnp SHARED ${SRC} ${HEADERS})

target_include_directories(rnp PRIVATE ${PROJECT_SOURCE_DIR}/rnp)
target_link_libraries(rnp
		PRIVATE
	Qt5::Core
	PkgConfig::QMF
	PkgConfig::SECRETS
        PkgConfig::RNP)

# Install the library
install(TARGETS rnp
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/qt5/plugins/messagingframework/crypto)
