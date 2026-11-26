Name:       sailfish-crypto-plugins

Summary:    Various plugins for cryptographic operations
Version:    0.1
Release:    1
License:    BSD3
URL:        https://github.com/dcaliste/sailfish-crypto-plugins
Source0:    %{name}-%{version}.tar.bz2
BuildRequires:  cmake
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Test)
BuildRequires:  pkgconfig(Qt5DBus)
BuildRequires:  pkgconfig(QmfClient)
BuildRequires:  pkgconfig(sailfishsecrets)
BuildRequires:  pkgconfig(sailfishcrypto)
BuildRequires:  pkgconfig(sailfishsecretspluginapi)
BuildRequires:  pkgconfig(sailfishcryptopluginapi)
BuildRequires:  pkgconfig(librnp)

%description
Implement cryptographic operations for email or secrets based on
various cryptographic libraries.

%package tests
Summary:    Tests for the RNP plugin
Requires:   sailfishsecretsdaemon
Requires:   libsailfishsecrets-tests
Requires:   libsailfishcrypto-tests
Requires:   dbus

%description tests
Unit tests of the RNP plugin, the plugin under its test name, and an
integration test against sailfishsecretsd --test.

%prep
%setup -q -n %{name}-%{version}

%build
%cmake .
%make_build

%install
%make_install

%files
%license LICENSE
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-rnp.so
%{_libdir}/qt5/plugins/messagingframework/crypto/*.so

%files tests
%{_libdir}/Sailfish/Crypto/libsailfishcrypto-rnp-test.so
/opt/tests/sailfish-crypto-plugins
