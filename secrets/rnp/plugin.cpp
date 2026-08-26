/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "rnpkeys.h"
#include "rnpffi.h"
#include "rnp_p.h"

class Q_DECL_EXPORT RnpPlugin
    : public QObject
    , public RnpFfi
    , public RnpKeys
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin Sailfish::Secrets::EncryptedStoragePlugin)
public:
    RnpPlugin(QObject *parent = nullptr)
        : QObject(parent)
        , RnpKeys(&m_rnp)
        , RnpFfi(&m_rnp)
        , m_rnp(Rnp::GPG_COMPAT)
    {
        qCDebug(lcSailfishCryptoPlugin) << "New RNP plugin" << &m_rnp;
    }
    ~RnpPlugin() {}

    QString name() const override {
#ifdef SAILFISHCRYPTO_TESTPLUGIN
        return QLatin1String("org.sailfishos.crypto.plugin.rnp.test");
#else
        return QLatin1String("org.sailfishos.crypto.plugin.rnp");
#endif
    }

    QString displayName() const override {
        return QStringLiteral("RNP");
    }

    int version() const override {
        return 000001;
    }

    Rnp m_rnp;
};

#include "plugin.moc"
