/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef PLUGIN_H
#define PLUGIN_H

#include "rnp_p.h"

#include <QObject>

#include <QMailMessage>
#include <QMailCrypto>

class QMailCryptoRNP : public QObject, public QMailCryptographicServiceInterface
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.qt-project.Qt.QMailCryptographicServiceInterface")
    Q_INTERFACES(QMailCryptographicServiceInterface)

public:
    QMailCryptoRNP();
    ~QMailCryptoRNP() {}

    void setPassphraseCallback(QMailCrypto::PassphraseCallback cb) override;
    QString passphraseCallback(const QString &info) const override;

    bool partHasSignature(const QMailMessagePartContainer &part) const override;
    QMailCrypto::VerificationResult verifySignature(const QMailMessagePartContainer &part) const override;
    QMailCrypto::SignatureResult sign(QMailMessagePartContainer *part, const QStringList &keys) const override;

    bool canDecrypt(const QMailMessagePartContainer &part) const override;
    QMailCrypto::DecryptionResult decrypt(QMailMessagePartContainer *part) const override;

private:
    QMailCrypto::SignatureResult computeSignature(QMailMessagePartContainer *part,
                                                  const QStringList &keys,
                                                  QByteArray *signedData,
                                                  QByteArray *micalg) const;

    Rnp m_rnp;
};

#endif
