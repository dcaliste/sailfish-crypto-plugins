/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef RNPFFI_H
#define RNPFFI_H

#include "Crypto/Plugins/extensionplugins.h"

class Rnp;

class Q_DECL_EXPORT RnpFfi
    : public Sailfish::Crypto::CryptoPlugin
{
public:
    RnpFfi(Rnp *rnp);
    ~RnpFfi();

    bool canStoreKeys() const override {
        return true;
    }

    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const override {
        return Sailfish::Crypto::CryptoPlugin::TrustedExecutionSoftwareEncryption;
    }

    Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            const QVariantMap &customParameters,
            QByteArray *randomData) override;

    Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate,
            const QVariantMap &customParameters) override;

    Sailfish::Crypto::Result generateInitializationVector(
            Sailfish::Crypto::CryptoManager::Algorithm algorithm,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            int keySize,
            const QVariantMap &customParameters,
            QByteArray *generatedIV) override;

    Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) override;

    Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata) override;

    Sailfish::Crypto::Result importKey(
            const QByteArray &data,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *importedKey);

    Sailfish::Crypto::Result importAndStoreKey(
            const QByteArray &data,
            const Sailfish::Crypto::Key &keyTemplate,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata);

    Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) override;

    // This doesn't exist - if you can store keys, then you must also
    // implement the Secrets::EncryptedStoragePlugin interface, and
    // stored key deletion will occur through that API instead.
    //Sailfish::Crypto::Result deleteStoredKey(
    //        const Sailfish::Crypto::Key::Identifier &identifier) override;

    Sailfish::Crypto::Result storedKeyIdentifiers(
            const QString &collectionName,
            const QVariantMap &customParameters,
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) override;

    Sailfish::Crypto::Result calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *digest) override;

    Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *signature) override;

    Sailfish::Crypto::Result verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) override;

    Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            QByteArray *encrypted,
            QByteArray *authenticationTag) override;

    Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QVariantMap &customParameters,
            QByteArray *decrypted,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) override;

    Sailfish::Crypto::Result initializeCipherSession(
            quint64 clientId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            quint32 *cipherSessionToken) override;

    Sailfish::Crypto::Result updateCipherSessionAuthentication(
            quint64 clientId,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken) override;

    Sailfish::Crypto::Result updateCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData) override;

    Sailfish::Crypto::Result finalizeCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) override;

private:
    Sailfish::Crypto::Result operation(Sailfish::Crypto::CryptoManager::Operation operation,
                                       const Sailfish::Crypto::Key &key,
                                       const QByteArray &data,
                                       const QVariantMap &customParameters,
                                       QByteArray *output);
    
    Rnp *m_rnp;
};

#endif
