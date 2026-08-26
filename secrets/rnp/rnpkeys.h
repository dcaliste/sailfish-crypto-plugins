/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef RNPKEYS_H
#define RNPKEYS_H

#include "Secrets/Plugins/extensionplugins.h"

class Rnp;

class Q_DECL_EXPORT RnpKeys
    : public Sailfish::Secrets::EncryptedStoragePlugin
{
public:
    RnpKeys(Rnp *rnp);
    ~RnpKeys();

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const override
    {
        return Sailfish::Secrets::StoragePlugin::FileSystemStorage;
    }

    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const override
    {
        return Sailfish::Secrets::EncryptionPlugin::TrustedExecutionSoftwareEncryption;
    }

    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const override
    {
        return Sailfish::Secrets::EncryptionPlugin::NoAlgorithm;
    }

    Sailfish::Secrets::Result collectionNames(QStringList *names) override;

    Sailfish::Secrets::Result createCollection(const QString &collectionName,
                                               const QByteArray &key) override;

    Sailfish::Secrets::Result removeCollection(const QString &collectionName) override;

    Sailfish::Secrets::Result isCollectionLocked(const QString &collectionName,
                                                 bool *locked) override;

    Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode,
                                                const QByteArray &salt,
                                                QByteArray *key) override;

    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName,
                                               const QByteArray &key) override;

    Sailfish::Secrets::Result reencrypt(const QString &collectionName,
                                        const QByteArray &oldkey,
                                        const QByteArray &newkey) override;

    Sailfish::Secrets::Result setSecret(const QString &collectionName,
                                        const QString &secretName,
                                        const QByteArray &secret,
                                        const Sailfish::Secrets::Secret::FilterData &filterData) override;

    Sailfish::Secrets::Result getSecret(const QString &collectionName,
                                        const QString &secretName,
                                        QByteArray *secret,
                                        Sailfish::Secrets::Secret::FilterData *filterData) override;

    Sailfish::Secrets::Result secretNames(const QString &collectionName,
                                          QStringList *secretNames) override;

    Sailfish::Secrets::Result findSecrets(const QString &collectionName,
                                          const Sailfish::Secrets::Secret::FilterData &filter,
                                          Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
                                          QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) override;

    Sailfish::Secrets::Result removeSecret(const QString &collectionName,
                                           const QString &secretName) override;

    // standalone secret operations.
    Sailfish::Secrets::Result setSecret(const QString &secretName,
                                        const QByteArray &secret,
                                        const Sailfish::Secrets::Secret::FilterData &filterData,
                                        const QByteArray &key) override;

    Sailfish::Secrets::Result accessSecret(const QString &secretName,
                                           const QByteArray &key,
                                           QByteArray *secret,
                                           Sailfish::Secrets::Secret::FilterData *filterData) override;

    Sailfish::Secrets::Result removeSecret(const QString &secretName) override;

    Sailfish::Secrets::Result reencryptSecret(const QString &secretName,
                                              const QByteArray &oldkey,
                                              const QByteArray &newkey) override;

 private:
    Rnp *m_rnp;
};

#endif
