cmake_minimum_required(VERSION 3.16)

project(sailfish-crypto-plugins
	VERSION 0.1
	DESCRIPTION "Plugins to use cryptography in emails or other parts.")

set(CMAKE_AUTOMOC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)

include(FeatureSummary)
include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

set(QT_MIN_VERSION "5.6.0")
find_package(Qt5 ${QT_MIN_VERSION} COMPONENTS Core REQUIRED)

pkg_check_modules(SECRETS sailfishsecrets sailfishcrypto IMPORTED_TARGET REQUIRED)
pkg_check_modules(QMF QmfClient IMPORTED_TARGET REQUIRED)
pkg_check_modules(RNP librnp IMPORTED_TARGET REQUIRED)

add_subdirectory(qmf)

feature_summary(WHAT ALL FATAL_ON_MISSING_REQUIRED_PACKAGES)
