/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "rnp_p.h"
#include "rnpffi.h"

#include <QTemporaryDir>

using namespace Sailfish::Crypto;

RnpFfi::RnpFfi(Rnp *rnp)
    : CryptoPlugin()
    , m_rnp(rnp)
{
    qCDebug(lcSailfishCryptoPlugin) << "New RNP ffi" << rnp;
}

RnpFfi::~RnpFfi()
{
}

Result RnpFfi::generateRandomData(quint64 callerIdent,
                                  const QString &csprngEngineName,
                                  quint64 numberBytes,
                                  const QVariantMap &customParameters,
                                  QByteArray *randomData)
{
    Q_UNUSED(callerIdent);
    Q_UNUSED(csprngEngineName);
    Q_UNUSED(numberBytes);
    Q_UNUSED(customParameters);
    Q_UNUSED(randomData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support generation of random data."));
}

Result RnpFfi::seedRandomDataGenerator(quint64 callerIdent,
                                       const QString &csprngEngineName,
                                       const QByteArray &seedData,
                                       double entropyEstimate,
                                       const QVariantMap &customParameters)
{
    Q_UNUSED(callerIdent);
    Q_UNUSED(csprngEngineName);
    Q_UNUSED(seedData);
    Q_UNUSED(entropyEstimate);
    Q_UNUSED(customParameters);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support generation of random data."));
}

Result RnpFfi::generateInitializationVector(CryptoManager::Algorithm algorithm,
                                            CryptoManager::BlockMode blockMode,
                                            int keySize,
                                            const QVariantMap &customParameters,
                                            QByteArray *generatedIV)
{
    Q_UNUSED(algorithm);
    Q_UNUSED(blockMode);
    Q_UNUSED(keySize);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedIV);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support generation of initialisation vector."));
}

static Result operationIsValid(CryptoManager::Operations operations,
                               const KeyPairGenerationParameters &kpgParams)
{
    if (!kpgParams.isValid()) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("invalid key generation parameters."));
    }
    if (kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairDsa
        && kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairRsa
        && kpgParams.keyPairType() != KeyPairGenerationParameters::KeyPairCustom) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("unsupported key pair algorithm."));
    }
    if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa
        && (operations & CryptoManager::OperationEncrypt)) {
        return Result(Result::CryptoPluginKeyGenerationError,
                      QStringLiteral("unsupported algorithm for operation."));
    }
    if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa) {
        DsaKeyPairGenerationParameters dkpgp(kpgParams);
        if (dkpgp.modulusLength() != 1024) {
            qCWarning(lcSailfishCryptoPlugin) << "RNP only support 1024 bits for DSA algorithm.";
        }
    }
    return Result();
}

// Result RnpFfi::generateSubkey(const Key &keyTemplate,
//                               const KeyPairGenerationParameters &kpgParams,
//                               Key *key,
//                               const QString &home)
// {
//     Result check = operationIsValid(keyTemplate.operations(), kpgParams);
//     if (check.code() != Result::Succeeded) {
//         return check;
//     }

    // GPGmeContext ctx(m_protocol, home);
    // if (!ctx) {
    //     return Result(Result::CryptoPluginKeyGenerationError, ctx.error());
    // }

    // GPGmeKey primary = GPGmeKey::fromUid(ctx, keyTemplate.collectionName());
    // if (!primary) {
    //     return Result(Result::StorageError,
    //                   QStringLiteral("cannot list keys from %1: %2.").arg(keyTemplate.collectionName()).arg(primary.error()));
    // }

    // GPGmeKeyEdit params(kpgParams, keyTemplate.operations());
    // GPGmeData out;
    // gpgme_error_t err;
    // err = gpgme_op_edit(ctx, primary, _edit_cb, &params, out);
    // if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    //     return Result(Result::CryptoPluginKeyGenerationError,
    //                   QStringLiteral("cannot edit key: %1").arg(gpgme_strerror(err)));
    // }

    // GPGmeKey gkey(ctx, primary.fingerprint());
    // if (!gkey) {
    //     return Result(Result::CryptoPluginKeyGenerationError,
    //                   QStringLiteral("cannot retrieve new key %1: %2.").arg(primary.fingerprint()).arg(gkey.error()));
    // }
    // // Assume new key is the last one.
    // while (gkey.sub && gkey.sub->next) {
    //     gkey.sub = gkey.sub->next;
    // }
    // gkey.toKey(key, this->name());
    // if (!home.isEmpty()) {
    //     key->setFilterData("Ephemeral-Home", home);
    // }

//     return Result();
// }

// Result RnpFfi::generateKey(const Key &keyTemplate,
//                            const KeyPairGenerationParameters &kpgParams,
//                            Key *key,
//                            const QString &home)
// {
//     Result check = operationIsValid(keyTemplate.operations(), kpgParams);
//     if (check.code() != Result::Succeeded) {
//         return check;
//     }
//     QVariantMap::ConstIterator name = kpgParams.customParameters().constFind("name");
//     if (m_protocol == GPGME_PROTOCOL_OpenPGP
//         && name == kpgParams.customParameters().constEnd()) {
//         return Result(Result::CryptoPluginKeyGenerationError,
//                       QStringLiteral("missing name custom parameter."));
//     }
//     QVariantMap::ConstIterator email = kpgParams.customParameters().constFind("email");
//     if (email == kpgParams.customParameters().constEnd()) {
//         return Result(Result::CryptoPluginKeyGenerationError,
//                       QStringLiteral("missing email custom parameter."));
//     }
//     QVariantMap::ConstIterator pass = kpgParams.customParameters().constFind("passphrase");
//     QString passphrase;
//     if (pass != kpgParams.customParameters().constEnd()) {
//         passphrase = pass->toString();
//     } else {
//         // If no password is given, either ask
//         // or check that empty passphrase is request
//         QVariantMap::ConstIterator empty = kpgParams.customParameters().constFind("emptyPassphrase");
//         if (empty == kpgParams.customParameters().constEnd()) {
//             Sailfish::Secrets::SecretManager secretManager;
//             Sailfish::Secrets::InteractionParameters uiParams;
//             uiParams.setOperation(Sailfish::Secrets::InteractionParameters::CreatePassword);
//             uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
//             uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::PasswordEcho);

//             Sailfish::Secrets::InteractionRequest request;
//             request.setInteractionParameters(uiParams);
//             request.setManager(&secretManager);

//             request.startRequest();
//             request.waitForFinished();
//             if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
//                 passphrase = request.userInput();
//             } else {
//                 return Result(Result::CryptoPluginKeyGenerationError,
//                               request.result().errorMessage());
//             }
//         }
//     }

    // GPGmeContext ctx(m_protocol, home);
    // if (!ctx) {
    //     return Result(Result::CryptoPluginKeyGenerationError, ctx.error());
    // }

    // QString gnupgKeyParms = "<GnupgKeyParms format=\"internal\">\n";
    // if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairDsa) {
    //     gnupgKeyParms += "Key-Type: DSA\n";
    //     gnupgKeyParms += "Key-Length: 1024\n";
    //     gnupgKeyParms += "Subkey-Type: DSA\n";
    //     gnupgKeyParms += "Subkey-Length: 1024\n";
    // } else if (kpgParams.keyPairType() == KeyPairGenerationParameters::KeyPairRsa) {
    //     RsaKeyPairGenerationParameters rkpgp(kpgParams);
    //     gnupgKeyParms += "Key-Type: RSA\n";
    //     gnupgKeyParms += QStringLiteral("Key-Length: %1\n").arg(rkpgp.modulusLength());
    //     gnupgKeyParms += "Subkey-Type: RSA\n";
    //     gnupgKeyParms += QStringLiteral("Subkey-Length: %1\n").arg(rkpgp.modulusLength());
    // } else {
    //     gnupgKeyParms += "Key-Type: default\n";
    // }
    // if (keyTemplate.operations() & CryptoManager::OperationSign) {
    //     gnupgKeyParms += "Key-Usage: sign\n";
    // }
    // else if (keyTemplate.operations() & CryptoManager::OperationEncrypt) {
    //     gnupgKeyParms += "Key-Usage: encrypt\n";
    // }
    // if (m_protocol == GPGME_PROTOCOL_OpenPGP) {
    //     gnupgKeyParms += QStringLiteral("Name-Real: %1\n").arg(name->toString());
    //     QVariantMap::ConstIterator comment = kpgParams.customParameters().constFind("comment");
    //     if (comment != kpgParams.customParameters().constEnd())
    //         gnupgKeyParms += QStringLiteral("Name-Comment: %1\n").arg(comment->toString());
    // }
    // gnupgKeyParms += QStringLiteral("Name-Email: %1\n").arg(email->toString());
    // QVariantMap::ConstIterator expire = kpgParams.customParameters().constFind("expire");
    // if (expire != kpgParams.customParameters().constEnd()) {
    //     gnupgKeyParms += QStringLiteral("Expire-Date: %1\n").arg(expire->toString());
    // }
    // if (!passphrase.isEmpty()) {
    //     gnupgKeyParms += QStringLiteral("Passphrase: %1\n").arg(passphrase);
    // }
    // gnupgKeyParms += QStringLiteral("</GnupgKeyParms>");

    // gpgme_error_t err;
    // if (m_protocol == GPGME_PROTOCOL_OpenPGP) {
    //     err = gpgme_op_genkey(ctx, gnupgKeyParms.toUtf8().constData(), 0, 0);
    // } else {
    //     GPGmeData pub, priv;
    //     if (!pub || !priv) {
    //         return Result(Result::CryptoPluginKeyGenerationError,
    //                       QStringLiteral("cannot create data."));
    //     }

    //     err = gpgme_op_genkey(ctx, gnupgKeyParms.toUtf8().constData(), pub, priv);

    //     // Todo do something with the public data which represent a
    //     // certificate request for S/MIME. Not implemented yet.
    // }
    // if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    //     return Result(Result::CryptoPluginKeyGenerationError,
    //                   QStringLiteral("cannot generate key: %1").arg(gpgme_strerror(err)));
    // }
    // gpgme_genkey_result_t result = gpgme_op_genkey_result(ctx);
    // GPGmeKey gkey(ctx, result->fpr);
    // if (!gkey) {
    //     return Result(Result::CryptoPluginKeyGenerationError,
    //                   QStringLiteral("cannot retrieve new key %1: %2.").arg(result->fpr).arg(gkey.error()));
    // }
    // gkey.toKey(key, this->name());
    // if (!home.isEmpty()) {
    //     key->setFilterData("Ephemeral-Home", home);
    // }

//     return Result();
// }

Result RnpFfi::generateKey(const Key &keyTemplate,
                           const KeyPairGenerationParameters &kpgParams,
                           const KeyDerivationParameters &skdfParams,
                           const QVariantMap &customParameters,
                           Key *key)
{
    Q_UNUSED(skdfParams);
    Q_UNUSED(customParameters);

    if (keyTemplate.collectionName().isEmpty()) {
        QTemporaryDir tmp;
        if (!tmp.isValid()) {
            return Result(Result::CryptoPluginKeyGenerationError,
                          QStringLiteral("cannot create temporary directory: %1.").arg(tmp.errorString()));
        }
        Result result; // = generateKey(keyTemplate, kpgParams, key, tmp.path());
        if (result.code() == Result::Succeeded) {
            tmp.setAutoRemove(false);
        }
        return result;
    } else {
        if (keyTemplate.filterData("Ephemeral-Home").isEmpty()) {
            return Result(Result::CryptoPluginKeyGenerationError,
                          QStringLiteral("cannot create subkey for %1: no home in template.").arg(keyTemplate.collectionName()));
        }
        // return generateSubkey(keyTemplate, kpgParams,
        //                       key, keyTemplate.filterData("Ephemeral-Home"));
        return Result();
    }
}

Result RnpFfi::generateAndStoreKey(const Key &keyTemplate,
                                   const KeyPairGenerationParameters &kpgParams,
                                   const KeyDerivationParameters &skdfParams,
                                   const QVariantMap &customParameters,
                                   Key *keyMetadata)
{
    Q_UNUSED(skdfParams);
    Q_UNUSED(customParameters);

    // if (keyTemplate.collectionName().isEmpty()
    //     || keyTemplate.collectionName().compare("import") == 0) {
    //     return generateKey(keyTemplate, kpgParams, keyMetadata, QString());
    // } else {
    //     return generateSubkey(keyTemplate, kpgParams, keyMetadata, QString());
    // }
    return Result();
}

// Result RnpFfi::downloadKey(const QString &fingerprint,
//                            const QStringList &urls,
//                            Key *importedKey,
//                            const QString &home)
// {
    // GPGmeContext ctx(m_protocol, home);
    // if (!ctx) {
    //     return Result(Result::StorageError, ctx.error());
    // }
    // GPGmeKey gkey(ctx, fingerprint);

    // for (QStringList::ConstIterator it = urls.constBegin();
    //      it != urls.constEnd(); it++) {
    //     QProcess gpgProcess;
    //     QStringList arguments;
    //     arguments << "--batch" << "--no-tty";
    //     if (!it->isEmpty()) {
    //         arguments << "--keyserver" << *it;
    //     }
    //     if (!gkey) {
    //         arguments << "--recv-keys" << fingerprint;
    //     } else {
    //         arguments << "--refresh" << fingerprint;
    //     }
    //     gpgProcess.start("/usr/bin/gpg2", arguments);
    //     gpgProcess.waitForFinished();
    //     if (gpgProcess.exitStatus() != QProcess::NormalExit) {
    //         switch (gpgProcess.error()) {
    //         case QProcess::FailedToStart:
    //             return Result(Result::CryptoPluginKeyImportError,
    //                           QStringLiteral("Cannot fetch key %1 from %2: failed to start.").arg(fingerprint).arg(*it));
    //         case QProcess::Crashed:
    //             return Result(Result::CryptoPluginKeyImportError,
    //                           QStringLiteral("Cannot fetch key %1 from %2: crashed.").arg(fingerprint).arg(*it));
    //         case QProcess::Timedout:
    //             return Result(Result::CryptoPluginKeyImportError,
    //                           QStringLiteral("Cannot fetch key %1 from %2: timed out.").arg(fingerprint).arg(*it));
    //         default:
    //             return Result(Result::CryptoPluginKeyImportError,
    //                           QStringLiteral("Cannot fetch key %1 from %2.").arg(fingerprint).arg(*it));
    //         }
    //     }
    //     if (gpgProcess.exitCode() == 0) {
    //         GPGmeKey gFetchedKey(ctx, fingerprint);
    //         if (!gFetchedKey) {
    //             return Result(Result::CryptoPluginKeyImportError,
    //                           QStringLiteral("Cannot fetch key %1 from %2: %3.").arg(fingerprint).arg(*it).arg(gFetchedKey.error()));
    //         }
    //         gFetchedKey.toKey(importedKey, name());

    //         return Result();
    //     }
    // }

//     return Result(Result::CryptoPluginKeyImportError,
//                   QStringLiteral("Cannot fetch key %1: not found from any server.").arg(fingerprint));
// }

// Result RnpFfi::importKey(const QByteArray &data,
//                          const QByteArray &passphrase,
//                          const QVariantMap &customParameters,
//                          Key *importedKey,
//                          const QString &home)
// {
//     Q_UNUSED(passphrase);

//     if (customParameters.contains("keyServers")) {
//         QStringList urls = customParameters.value("keyServers").toStringList();
//         if (urls.isEmpty()) {
//             urls << ""; // Will use default servers on empty url.
//         }
        //return downloadKey(data, urls, importedKey, home);
    // }

    // GPGmeContext ctx(m_protocol, home);
    // if (!ctx) {
    //     return Result(Result::StorageError, ctx.error());
    // }

    // GPGmeData gdata(data);
    // if (!gdata) {
    //     return Result(Result::CryptoPluginKeyImportError,
    //                   QStringLiteral("cannot create data: %1.").arg(gdata.error()));
    // }

    // gpgme_error_t err;
    // err = gpgme_op_import(ctx, gdata);
    // if (gpgme_err_code(err) != GPG_ERR_NO_ERROR) {
    //     return Result(Result::CryptoPluginKeyImportError,
    //                   QStringLiteral("cannot import data: %1.").arg(gpgme_strerror(err)));
    // }
    // gpgme_import_result_t result;
    // result = gpgme_op_import_result(ctx);
    // if (!result) {
    //     return Result(Result::CryptoPluginKeyImportError, "cannot get result.");
    // }
    // gpgme_import_status_t status = result->imports;
    // const char *fingerprint = (const char*)0;
    // while (status) {
    //     if (gpgme_err_code(status->result) != GPG_ERR_NO_ERROR) {
    //         return Result(Result::CryptoPluginKeyImportError,
    //                       QStringLiteral("failing importing data: %1.").arg(gpgme_strerror(status->result)));
    //     }
    //     if (!fingerprint) {
    //         fingerprint = status->fpr;
    //     }
    //     status = status->next;
    // }
    // if (!fingerprint) {
    //     return Result(Result::CryptoPluginKeyImportError,
    //                   QStringLiteral("no key in the imported data."));
    // }

    // GPGmeKey gFetchedKey(ctx, fingerprint);
    // if (!gFetchedKey) {
    //     return Result(Result::CryptoPluginKeyImportError,
    //                   QStringLiteral("Cannot import key %1 from data: %2.").arg(fingerprint).arg(gFetchedKey.error()));
    // }
    // gFetchedKey.toKey(importedKey, name());

//     return Result();
// }

Result RnpFfi::importKey(const QByteArray &data,
                         const QByteArray &passphrase,
                         const QVariantMap &customParameters,
                         Key *importedKey)
{
    QTemporaryDir tmp;
    if (!tmp.isValid()) {
        return Result(Result::CryptoPluginKeyImportError,
                      QStringLiteral("cannot create temporary directory: %1.").arg(tmp.errorString()));
    }
    // Result result = importKey(data, passphrase, customParameters, importedKey, tmp.path());
    // if (result.code() == Result::Succeeded) {
    //     tmp.setAutoRemove(false);
    // }
    // return result;
    return Result();
}

Result RnpFfi::importAndStoreKey(const QByteArray &data,
                                 const Key &keyTemplate,
                                 const QByteArray &passphrase,
                                 const QVariantMap &customParameters,
                                 Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);

    // return importKey(data, passphrase, customParameters, keyMetadata, QString());
    return Result();
}

Result RnpFfi::storedKey(const Key::Identifier &identifier,
                         Key::Components keyComponents,
                         const QVariantMap &customParameters,
                         Key *key)
{
    // GPGmeContext ctx(m_protocol, customParameters.value("Ephemeral-Home",
    //                                                     QVariant(QString())).toString());
    // if (!ctx) {
    //     return Result(Result::StorageError, ctx.error());
    // }

    // GPGmeKey gkey(ctx, identifier.name(),
    //               (keyComponents & Key::SecretKeyData)
    //               ? GPGmeKey::Secret : GPGmeKey::Public);
    // if (!gkey) {
    //     return Result(Result::InvalidKeyIdentifier,
    //                   Sailfish::Secrets::Result::InvalidSecretError,
    //                   QStringLiteral("cannot retrieve key %1: %2.").arg(identifier.name()).arg(gkey.error()));
    // }
    // gkey.toKey(key, name());

    return Result();
}

Result RnpFfi::storedKeyIdentifiers(const QString &collectionName,
                                    const QVariantMap &customParameters,
                                    QVector<Key::Identifier> *identifiers)
{
    if (collectionName.compare("import") == 0) {
        // This is a fake collection to allow importation of new keys,
        // see gpgmestorage().
        return Result();
    }

    const QStringList ids = collectionName.isEmpty() ? m_rnp->publicKeyring().keyids() : (QStringList() << collectionName);

    for (const QString &id : ids) {
        Rnp::Key primary = m_rnp->publicKeyring().key(id);
        for (const QString &fp : primary.fingerprints()) {
            identifiers->append(Key::Identifier(fp, id, name()));
        }
    }

    return Result();
}

Result RnpFfi::calculateDigest(const QByteArray &data,
                               CryptoManager::SignaturePadding padding,
                               CryptoManager::DigestFunction digestFunction,
                               const QVariantMap &customParameters,
                               QByteArray *digest)
{
    Q_UNUSED(data);
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);
    Q_UNUSED(digest);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support diggest."));
}

Result RnpFfi::operation(CryptoManager::Operation operation,
                         const Key &key,
                         const QByteArray &data,
                         const QVariantMap &customParameters,
                         QByteArray *output)
{
    Result::ErrorCode errCode;
    if (operation == CryptoManager::OperationSign) {
        errCode = Result::CryptoPluginSigningError;
    } else if (operation == CryptoManager::OperationEncrypt) {
        errCode = Result::CryptoPluginEncryptionError;
    } else {
        return Result(Result::OperationNotSupportedError,
                      QStringLiteral("Operation not supported by RNP plugin."));
    }

    if (!output) {
        return Result(errCode, QStringLiteral("missing output argument."));
    }
    output->clear();

    if (key.storagePluginName() != name()) {
        return Result(errCode, QStringLiteral("cannot use a non RNP key."));
    }

    Rnp::Key keys[2];
    if (operation == CryptoManager::OperationSign) {
        keys[0] = m_rnp->secretKeyring().key(key);
        *output = m_rnp->sign(data, keys,
                              customParameters.value("With-Armor",
                                                     QVariant(true)).toBool());
        if (output->isEmpty()) {
            return Result(errCode, QStringLiteral("cannot sign data."));
        }
    } else if (operation == CryptoManager::OperationEncrypt) {
        Rnp::Key signers;
        keys[0] = m_rnp->publicKeyring().key(key);
        *output = m_rnp->encrypt(data, keys, &signers,
                                 customParameters.value("With-Armor",
                                                        QVariant(true)).toBool());
        if (output->isEmpty()) {
            return Result(errCode, QStringLiteral("cannot encrypt data."));
        }
    }

    return Result();
}

Result RnpFfi::sign(const QByteArray &data,
                    const Key &key,
                    CryptoManager::SignaturePadding padding,
                    CryptoManager::DigestFunction digestFunction,
                    const QVariantMap &customParameters,
                    QByteArray *signature)
{
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);

    return operation(CryptoManager::OperationSign,
                     key, data, customParameters, signature);
}

Result RnpFfi::verify(const QByteArray &signature,
                      const QByteArray &data,
                      const Key &key,
                      CryptoManager::SignaturePadding padding,
                      CryptoManager::DigestFunction digestFunction,
                      const QVariantMap &customParameters,
                      CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);

    if (!verificationStatus) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("missing verificationStatus argument."));
    }
    *verificationStatus = CryptoManager::VerificationStatusUnknown;

    if (key.storagePluginName() != name()) {
        return Result(Result::CryptoPluginVerificationError,
                      QStringLiteral("cannot verify with a non RNP key."));
    }

    const QList<Rnp::Signature> signers = m_rnp->verify(data, signature);
    for (const Rnp::Signature &sig : signers) {
        if (key.collectionName() == sig.keyid &&
            key.name() == sig.fingerprint) {
            if (sig.status == Rnp::Signature::VALID)
                *verificationStatus = CryptoManager::VerificationSucceeded;
            else if (sig.status == Rnp::Signature::EXPIRED)
                *verificationStatus = CryptoManager::VerificationKeyExpired;
            else if (sig.status == Rnp::Signature::KEY_NOT_FOUND)
                *verificationStatus = CryptoManager::VerificationKeyInvalid;
            else if (sig.status == Rnp::Signature::INVALID)
                *verificationStatus = CryptoManager::VerificationFailed;
            return Result();
        }
    }
    return Result();
}

Result RnpFfi::encrypt(const QByteArray &data,
                       const QByteArray &iv,
                       const Key &key,
                       CryptoManager::BlockMode blockMode,
                       CryptoManager::EncryptionPadding padding,
                       const QByteArray &authenticationData,
                       const QVariantMap &customParameters,
                       QByteArray *encrypted,
                       QByteArray *authenticationTag)
{
    Q_UNUSED(iv);
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);
    Q_UNUSED(authenticationData);
    Q_UNUSED(authenticationTag);

    return operation(CryptoManager::OperationEncrypt,
                     key, data, customParameters, encrypted);
}

Result RnpFfi::decrypt(const QByteArray &data,
                       const QByteArray &iv,
                       const Key &key, // or keyreference, i.e. Key(keyName)
                       CryptoManager::BlockMode blockMode,
                       CryptoManager::EncryptionPadding padding,
                       const QByteArray &authenticationData,
                       const QByteArray &authenticationTag,
                       const QVariantMap &customParameters,
                       QByteArray *decrypted,
                       CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(iv);
    Q_UNUSED(blockMode);
    Q_UNUSED(padding);
    Q_UNUSED(authenticationData);
    Q_UNUSED(authenticationTag);
    Q_UNUSED(customParameters);

    if (!verificationStatus) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("missing verificationStatus argument."));
    }
    *verificationStatus = CryptoManager::VerificationStatusUnknown;

    if (key.storagePluginName() != name()) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("cannot decrypt with a non RNP key."));
    }

    QList<Rnp::Signature> signers;
    *decrypted = m_rnp->decrypt(data, &signers);
    if (decrypted->isEmpty()) {
        return Result(Result::CryptoPluginDecryptionError,
                      QStringLiteral("cannot decrypt data."));
    }
    for (const Rnp::Signature &sig : signers) {
        if (key.collectionName() == sig.keyid &&
            key.name() == sig.fingerprint) {
            if (sig.status == Rnp::Signature::VALID)
                *verificationStatus = CryptoManager::VerificationSucceeded;
            else if (sig.status == Rnp::Signature::EXPIRED)
                *verificationStatus = CryptoManager::VerificationKeyExpired;
            else if (sig.status == Rnp::Signature::KEY_NOT_FOUND)
                *verificationStatus = CryptoManager::VerificationKeyInvalid;
            else if (sig.status == Rnp::Signature::INVALID)
                *verificationStatus = CryptoManager::VerificationFailed;
            return Result();
        }
    }
    return Result();
}

Result RnpFfi::initializeCipherSession(quint64 clientId,
                                       const QByteArray &iv,
                                       const Key &key, // or keyreference, i.e. Key(keyName)
                                       CryptoManager::Operation operation,
                                       CryptoManager::BlockMode blockMode,
                                       CryptoManager::EncryptionPadding encryptionPadding,
                                       CryptoManager::SignaturePadding signaturePadding,
                                       CryptoManager::DigestFunction digestFunction,
                                       const QVariantMap &customParameters,
                                       quint32 *cipherSessionToken)
{
    Q_UNUSED(clientId);
    Q_UNUSED(iv);
    Q_UNUSED(key);
    Q_UNUSED(operation);
    Q_UNUSED(blockMode);
    Q_UNUSED(encryptionPadding);
    Q_UNUSED(signaturePadding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(customParameters);
    Q_UNUSED(cipherSessionToken);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support cipher."));
}

Result RnpFfi::updateCipherSessionAuthentication(quint64 clientId,
                                                 const QByteArray &authenticationData,
                                                 const QVariantMap &customParameters,
                                                 quint32 cipherSessionToken)
{
    Q_UNUSED(clientId);
    Q_UNUSED(authenticationData);
    Q_UNUSED(customParameters);
    Q_UNUSED(cipherSessionToken);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support cipher."));
}

Result RnpFfi::updateCipherSession(quint64 clientId,
                                   const QByteArray &data,
                                   const QVariantMap &customParameters,
                                   quint32 cipherSessionToken,
                                   QByteArray *generatedData)
{
    Q_UNUSED(clientId);
    Q_UNUSED(data);
    Q_UNUSED(cipherSessionToken);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedData);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support cipher."));
}

Result RnpFfi::finalizeCipherSession(quint64 clientId,
                                     const QByteArray &data,
                                     const QVariantMap &customParameters,
                                     quint32 cipherSessionToken,
                                     QByteArray *generatedData,
                                     CryptoManager::VerificationStatus *verificationStatus)
{
    Q_UNUSED(clientId);
    Q_UNUSED(data);
    Q_UNUSED(cipherSessionToken);
    Q_UNUSED(customParameters);
    Q_UNUSED(generatedData);
    Q_UNUSED(verificationStatus);
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The RNP plugin doesn't support cipher."));
}
