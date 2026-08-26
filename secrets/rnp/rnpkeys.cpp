/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "rnpkeys.h"
#include "rnp_p.h"

#include <Crypto/Plugins/extensionplugins.h>

using namespace Sailfish::Secrets;

RnpKeys::RnpKeys(Rnp *rnp)
    : EncryptedStoragePlugin()
    , m_rnp(rnp)
{
}

RnpKeys::~RnpKeys()
{
}

Result RnpKeys::collectionNames(QStringList *names)
{
    names->clear();

    if (!m_rnp->publicKeyring().isValid())
        return Result(Result::DatabaseError,
                      QStringLiteral("failed to open keyring at path '%1'.").arg(m_rnp->publicKeyring().path()));

    for (const QString &id : m_rnp->publicKeyring().keyids()) {
        names->append(id);
    }

    // Append a generic collection name to be able to import keys
    // into a collection that does not exist yet.
    names->append(QString::fromLatin1("import"));

    return Result();
}

Result RnpKeys::createCollection(const QString &collectionName,
                                 const QByteArray &key)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support collection creation."));
}

Result RnpKeys::removeCollection(const QString &collectionName)
{
    return removeSecret(collectionName, QString());
}

Result RnpKeys::isCollectionLocked(const QString &collectionName,
                                   bool *locked)
{
    Q_UNUSED(collectionName);

    // GnuPG keys are never locked by the plugin, they are locked externally
    // and will be unlocked by the pinentry.
    if (locked) {
        *locked = false;
    }
    return Result();
}

Result RnpKeys::deriveKeyFromCode(const QByteArray &authenticationCode,
                                  const QByteArray &salt,
                                  QByteArray *key)
{
    Q_UNUSED(authenticationCode);
    Q_UNUSED(salt);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support encryption key."));
}

Result RnpKeys::setEncryptionKey(const QString &collectionName,
                                 const QByteArray &key)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support encryption key."));
}


Result RnpKeys::reencrypt(const QString &collectionName,
                          const QByteArray &oldkey,
                          const QByteArray &newkey)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(oldkey);
    Q_UNUSED(newkey);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support encryption key."));
}

Result RnpKeys::setSecret(const QString &collectionName,
                          const QString &secretName,
                          const QByteArray &secret,
                          const Secret::FilterData &filterData)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support lambda secrets."));
}

Result RnpKeys::getSecret(const QString &collectionName,
                          const QString &secretName,
                          QByteArray *secret,
                          Secret::FilterData *filterData)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support lambda secrets."));
}

Result RnpKeys::secretNames(const QString &collectionName,
                            QStringList *secretNames)
{
    secretNames->clear();
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see collectionNames().
        return Result();
    }

    if (!m_rnp->publicKeyring().isValid())
        return Result(Result::DatabaseError,
                      QStringLiteral("failed to open keyring at path '%1'.").arg(m_rnp->publicKeyring().path()));
    Rnp::Key key = m_rnp->publicKeyring().key(collectionName);
    if (!key.isValid())
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("no collection %1.").arg(collectionName));

    *secretNames = key.fingerprints();

    return Result();
}

static bool matchRule(const Sailfish::Crypto::Key::FilterData &keyData,
                      Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                      const QString &filter, const QString &value)
{
    if (filter.compare("email") == 0) {
        return keyData.contains("User-Emails")
            && keyData.value("User-Emails").split(',', QString::SkipEmptyParts).contains(value);
    } else if (filter.compare("canSign") == 0) {
        return true;
    } else if (filter.compare("canEncrypt") == 0) {
        return algorithm == Sailfish::Crypto::CryptoManager::AlgorithmUnknown;
    } else {
        return keyData.contains(filter)
            && (keyData.value(filter).compare(value) == 0);
    }
}

Result RnpKeys::findSecrets(const QString &collectionName,
                            const Secret::FilterData &filter,
                            StoragePlugin::FilterOperator filterOperator,
                            QVector<Secret::Identifier> *identifiers)
{
    qCDebug(lcSailfishCryptoPlugin) << "findSecrets request" << collectionName;
    identifiers->clear();

    if (!m_rnp->publicKeyring().isValid())
        return Result(Result::DatabaseError,
                      QStringLiteral("failed to open keyring at path '%1'.").arg(m_rnp->publicKeyring().path()));

    // Import is a fake collection name to allow to search in every collections.
    const QStringList ids = collectionName.compare("import") ? m_rnp->publicKeyring().keyids() : (QStringList() << collectionName);
    for (const QString &id : ids) {
        Rnp::Key primary = m_rnp->publicKeyring().key(id);
        for (const QString &fp : primary.fingerprints()) {
            Rnp::Key k = primary.subkey(fp);
            Sailfish::Crypto::Key key = k.toCryptoKey(name());
            bool match = false;
            const Sailfish::Crypto::Key::FilterData &keyData = key.filterData();
            switch (filterOperator) {
            case SecretManager::OperatorOr:
                match = false;
                for (Secret::FilterData::ConstIterator it = filter.constBegin();
                     it != filter.constEnd() && !match; it++) {
                    match = matchRule(keyData, key.algorithm(), it.key(), it.value());
                }
                break;
            case SecretManager::OperatorAnd:
                match = true;
                for (Secret::FilterData::ConstIterator it = filter.constBegin();
                     it != filter.constEnd() && match; it++) {
                    match = matchRule(keyData, key.algorithm(), it.key(), it.value());
                }
                break;
            }
            if (match) {
                identifiers->append(Secret::Identifier(key.name(),
                                                       key.collectionName(), name()));
            }
        }
    }

    return Result();
}

Result RnpKeys::removeSecret(const QString &collectionName,
                             const QString &secretName)
{
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see collectionNames().
        return Result();
    }

    if (!m_rnp->publicKeyring().isValid())
        return Result(Result::DatabaseError,
                      QStringLiteral("failed to open keyring at path '%1'.").arg(m_rnp->publicKeyring().path()));

    Rnp::Key key = m_rnp->publicKeyring().key(collectionName);
    if (!key.isValid()) {
        return Result(Result::InvalidCollectionError,
                      QStringLiteral("no collection %1.").arg(collectionName));
    }

    if (key.fingerprint() == secretName || secretName.isEmpty()) {
        if (!m_rnp->publicKeyring().remove(key)) {
            return Result(Result::DatabaseError,
                          QStringLiteral("cannot delete key %1.").arg(secretName));
        }
    } else {
        Rnp::Key sub = key.subkey(secretName);
        if (!m_rnp->publicKeyring().remove(sub)) {
            return Result(Result::DatabaseError,
                          QStringLiteral("cannot delete subkey %1.").arg(secretName));
        }
    }
    return Result();
}

// standalone secret operations.
Result RnpKeys::setSecret(const QString &secretName,
                          const QByteArray &secret,
                          const Secret::FilterData &filterData,
                          const QByteArray &key)
{
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    Q_UNUSED(key);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support lambda secrets."));
}


Result RnpKeys::accessSecret(const QString &secretName,
                             const QByteArray &key,
                             QByteArray *secret,
                             Secret::FilterData *filterData)
{
    Q_UNUSED(secretName);
    Q_UNUSED(key);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support lambda secrets."));
}

Result RnpKeys::removeSecret(const QString &secretName)
{
    return removeSecret(QString(), secretName);
}

Result RnpKeys::reencryptSecret(const QString &secretName,
                                const QByteArray &oldkey,
                                const QByteArray &newkey)
{
    Q_UNUSED(secretName);
    Q_UNUSED(oldkey);
    Q_UNUSED(newkey);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support lambda secrets."));
}
