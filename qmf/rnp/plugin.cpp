/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#include "rnp_p.h"

#include <qmaillog.h>

static QByteArray canonicalizeStr(const char *str)
{
    QByteArray out;
    out.reserve(strlen(str) * 1.1);

    for (const char *p = str; *p != '\0'; ++p) {
        if (*p != '\r') {
            if (*p == '\n')
                out.append('\r');
            out.append(*p);
        }
    }

    return out;
}

static QMailCrypto::SignatureResult toSignatureResult(Rnp::Signature::Status status)
{
    switch (status) {
    case Rnp::Signature::VALID:
        return QMailCrypto::SignatureValid;
    case Rnp::Signature::EXPIRED:
        return QMailCrypto::SignatureExpired;
    case Rnp::Signature::KEY_NOT_FOUND:
        return QMailCrypto::MissingKey;
    case Rnp::Signature::INVALID:
        return QMailCrypto::BadSignature;
    default:
        return QMailCrypto::UnknownError;
    }
}

QMailCryptoRNP::QMailCryptoRNP()
    : QObject()
    , QMailCryptographicServiceInterface()
{
}

bool QMailCryptoRNP::partHasSignature(const QMailMessagePartContainer &part) const
{
    if (part.multipartType() != QMailMessagePartContainer::MultipartSigned || part.partCount() != 2)
        return false;

    const QMailMessagePart signature = part.partAt(1);

    if (!signature.contentType().matches("application", "pgp-signature"))
        return false;

    return true;
}

QMailCrypto::VerificationResult QMailCryptoRNP::verifySignature(const QMailMessagePartContainer &part) const
{
    if (!partHasSignature(part))
        return QMailCrypto::VerificationResult(QMailCrypto::MissingSignature);

    QMailMessagePart body = part.partAt(0);
    QMailMessagePart signature = part.partAt(1);

    if (!body.contentAvailable() || !signature.contentAvailable())
        return QMailCrypto::VerificationResult();

    QMailCrypto::VerificationResult result;
    result.engine = QStringLiteral("librnp.so");

    Rnp rnp(Rnp::GPG_COMPAT);
    const QList<Rnp::Signature> sigs = rnp.verify(canonicalizeStr(body.undecodedData()),
                                                  signature.body().data(QMailMessageBody::Decoded));
    result.summary = sigs.length() > 0 ? QMailCrypto::SignatureValid : QMailCrypto::BadSignature;
    for (const Rnp::Signature &sig : sigs) {
        result.keyResults.append(QMailCrypto::KeyResult(sig.fingerprint.isEmpty() ? sig.keyid : sig.fingerprint,
                                                        toSignatureResult(sig.status),
                                                        QVariantMap()));
        if (sig.status != Rnp::Signature::VALID)
            result.summary = toSignatureResult(sig.status);
    }
    return result;
}

QMailCrypto::SignatureResult QMailCryptoRNP::sign(QMailMessagePartContainer *part, const QStringList &keys) const
{
    if (!part) {
        qCWarning(lcMessaging) << "unable to sign a NULL part.";
        return QMailCrypto::UnknownError;
    }

    Rnp rnp(Rnp::GPG_COMPAT);

    /* Fetch the secret keys. */
    Rnp::Key signers[keys.length() + 1];
    size_t i = 0;
    for (const QString &fp : keys) {
        signers[i] = rnp.secretKeyring().fromFingerprint(fp);
        if (!signers[i].isValid()) {
            return QMailCrypto::MissingKey;
        }
        i += 1;
    }

    /* Generate the part to sign into data. */
    QMailMessagePart data;
    if (!partHasSignature(*part)) {
        data.setMultipartType(part->multipartType());
        if (part->multipartType() == QMailMessagePartContainer::MultipartNone) {
            data.setBody(part->body());
        } else {
            for (uint i = 0; i < part->partCount(); i++)
                data.appendPart(part->partAt(i));
        }
    } else {
        data = part->partAt(0);
    }
    QByteArray message = data.toRfc2822();
    data.setUndecodedData(message);

    const QByteArray signedData = rnp.sign(canonicalizeStr(message.data()), signers, true);
    if (signedData.isEmpty()) {
        return QMailCrypto::UnknownError;
    }

    /* Change the part object to have two parts, if not already. */
    if (!partHasSignature(*part)) {
        if (part->multipartType() != QMailMessagePartContainer::MultipartNone) {
            // Erase content.
            part->clearParts();
        }
        // Setup new two parts content.
        part->appendPart(data);
        QMailMessagePart signature;
        part->appendPart(signature);
    }

    // Set it to multipart/signed content-type.
    QList<QMailMessageHeaderField::ParameterType> parameters;
    parameters << QMailMessageHeaderField::ParameterType("micalg", "pgp-sha256");
    parameters << QMailMessageHeaderField::ParameterType("protocol", "application/pgp-signature");
    part->setMultipartType(QMailMessagePartContainer::MultipartSigned, parameters);

    // Write the signature data in the second part.
    QMailMessagePart &signature = part->partAt(1);

    signature.setBody(QMailMessageBody::fromData(signedData,
                                                 QMailMessageContentType("application/pgp-signature"),
                                                 QMailMessageBody::SevenBit));
    signature.setContentDescription("OpenPGP digital signature");

    return QMailCrypto::SignatureValid;
}

bool QMailCryptoRNP::canDecrypt(const QMailMessagePartContainer &part) const
{
    if (part.isEncrypted()) {
        const QMailMessagePart &control = part.partAt(0);
        if (control.contentType().matches("application", "pgp-encrypted")
            && control.hasBody()) {
            return control.body().data().startsWith(QString::fromLatin1("Version: 1"));
        }
    }
    return false;
}

QMailCrypto::DecryptionResult QMailCryptoRNP::decrypt(QMailMessagePartContainer *part) const
{
    if (!part) {
        qCWarning(lcMessaging) << "unable to decrypt a NULL part.";
        return QMailCrypto::DecryptionResult();
    }

    if (!canDecrypt(*part))
        return QMailCrypto::DecryptionResult(QMailCrypto::UnsupportedProtocol);

    const QMailMessagePart &body = part->partAt(1);

    if (!body.contentAvailable())
        return QMailCrypto::DecryptionResult();

    Rnp rnp(Rnp::GPG_COMPAT);
    const QByteArray decData = rnp.decrypt(body.body().data(QMailMessageBody::Decoded));
    QMailCrypto::DecryptionResult result;
    result.engine = QStringLiteral("librnp.so");
    if (!decData.isEmpty()) {
        const QMailMessage mail = QMailMessage::fromRfc2822(decData);

        part->clearParts();
        if (mail.partCount() > 0) {
            part->setMultipartType(mail.multipartType(),
                                   mail.contentType().parameters());
            for (uint i = 0; i < mail.partCount(); i++) {
                part->appendPart(mail.partAt(i));
            }
        } else {
            part->setBody(mail.body());
        }

        result.status = QMailCrypto::Decrypted;
    } else {
        result.status = QMailCrypto::UnknownCryptError;
    }
    return result;
}

void QMailCryptoRNP::setPassphraseCallback(QMailCrypto::PassphraseCallback cb)
{
    Q_UNUSED(cb);

    qCWarning(lcRnp) << "passphrase callback not implemented.";
}

QString QMailCryptoRNP::passphraseCallback(const QString &info) const
{
    Q_UNUSED(info);

    qCWarning(lcRnp) << "passphrase callback not implemented.";
    return QString();
}
