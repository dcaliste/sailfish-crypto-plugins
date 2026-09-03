/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "rnp_p.h"

#include <rnp/rnp_err.h>

#include <QDir>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <Crypto/Plugins/extensionplugins.h>
#include <Secrets/secretmanager.h>
#include <Secrets/interactionrequest.h>

Q_LOGGING_CATEGORY(lcRnp, "org.sailfish.crypto.rnp", QtWarningMsg)

static bool unlock(rnp_ffi_t        ffi,
                   void *           app_ctx,
                   rnp_key_handle_t key,
                   const char *     pgp_context,
                   char             buf[],
                   size_t           buf_len)
{
    Q_UNUSED(ffi);
    Q_UNUSED(app_ctx);

    QString fp;
    char *fprint = nullptr;
    if (rnp_key_get_fprint(key, &fprint) == RNP_SUCCESS) {
        fp = QString::fromLatin1(fprint);
        rnp_buffer_destroy(fprint);
    }
    qCDebug(lcRnp) << "needing a password for key" << fp << " within context" << pgp_context;

    Sailfish::Secrets::SecretManager secretManager;

    // bool useCache = m_useCache->value(QVariant(true)).toBool();
    // if (useCache && cacheId.isValid() && prompt.instruction().isEmpty()) {
    //     Sailfish::Secrets::StoredSecretRequest request;
    //     qCDebug(lcRnp) << "Starting cache request for" << cacheId.name();
    //     request.setManager(&secretManager);
    //     request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    //     request.setIdentifier(cacheId);
    //     request.startRequest();
    //     request.waitForFinished();
    //     qCDebug(lcRnp) << "-> return code" << request.result().code();
    //     qCDebug(lcRnp) << request.result().errorMessage();
    //     if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
    //         qCDebug(lcRnp) << "found cached secret";
    //         *passphrase = request.secret().data();
    //         return request.result();
    //     } else if (request.result().code() == Sailfish::Secrets::Result::Failed
    //                && request.result().errorCode() == Sailfish::Secrets::Result::InteractionViewUserCanceledError) {
    //         // Later on, in case of a valid key, don't ask again the
    //         // user to grant access to key caching.
    //         useCache = false;
    //     }
    // }

    Sailfish::Secrets::InteractionParameters::PromptText prompt;
    if (!strcmp(pgp_context, "sign"))
        prompt.setInstruction(QStringLiteral("Unlock key %1 to sign").arg(fp.right(8)));
    else if (!strcmp(pgp_context, "decrypt"))
        prompt.setInstruction(QStringLiteral("Unlock key %1 to decrypt").arg(fp.right(8)));

    Sailfish::Secrets::InteractionParameters uiParams;
    uiParams.setPromptText(prompt);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::PasswordEcho);

    Sailfish::Secrets::InteractionRequest request;
    request.setInteractionParameters(uiParams);
    request.setManager(&secretManager);

    qCDebug(lcRnp) << "Starting passphrase request";
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Succeeded) {
        QByteArray passphrase = request.userInput();
        if ((size_t)passphrase.length() < buf_len) {
            memcpy(buf, passphrase.data(), passphrase.length() + 1);
        }
        passphrase.fill('x'); // Erase the passphrase from memory.
        // if (useCache && cacheId.isValid() && ensureCacheCollection()) {
        //     Sailfish::Secrets::StoreSecretRequest store;
        //     // store.setInteractionParameters(uiParams);

        //     store.setManager(&secretManager);
        //     store.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
        //     store.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);

        //     Sailfish::Secrets::Secret pin(cacheId);
        //     pin.setType(Sailfish::Secrets::Secret::TypeBlob);
        //     pin.setData(request.userInput());
        //     store.setSecret(pin);

        //     qCDebug(lcRnp) << "Storing passphrase for" << cacheId.name();
        //     store.startRequest();
        //     store.waitForFinished();
        //     qCDebug(lcRnp) << "-> return code" << store.result().code();
        //     if (store.result().code() != Sailfish::Secrets::Result::Succeeded)
        //         qCWarning(lcRnp) << store.result().errorMessage();
        // }
    }

    return request.result().code() == Sailfish::Secrets::Result::Succeeded;
}

Rnp::Rnp(Rnp::Format format)
    : m_format(format)
{
    if (format == Rnp::GPG_COMPAT) {
        rnp_ffi_create(&m_ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG);
        m_keyringPath = QDir::home().absoluteFilePath(".gnupg");
        m_publicKeyPath = QDir::home().absoluteFilePath(".gnupg/pubring.gpg");
        m_secretKeyPath = QDir::home().absoluteFilePath(".gnupg/secring.gpg");
    } else {
        rnp_ffi_create(&m_ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX);
        m_keyringPath = QDir::home().absoluteFilePath(".rnp");
        m_publicKeyPath = QDir::home().absoluteFilePath(".gnupg/pubring.kbx");
        m_secretKeyPath = QDir::home().absoluteFilePath(".gnupg/secring.kbx");
    }
    rnp_ffi_set_pass_provider(m_ffi, unlock, this);
}

Rnp::~Rnp()
{
    delete m_publicKeyring;
    delete m_secretKeyring;
    rnp_ffi_destroy(m_ffi);
}

Rnp::Keyring& Rnp::publicKeyring() const
{
    if (!m_publicKeyring)
        m_publicKeyring = new Keyring(this, Keyring::PUBLIC);
    return *m_publicKeyring;
}

Rnp::Keyring& Rnp::secretKeyring() const
{
    if (!m_secretKeyring)
        m_secretKeyring = new Keyring(this, Keyring::SECRET);
    return *m_secretKeyring;
}

QStringList Rnp::importKeys(const QByteArray &data)
{
    if (!m_publicKeyring)
        m_publicKeyring = new Keyring(this, Keyring::PUBLIC);
    if (!m_secretKeyring)
        m_secretKeyring = new Keyring(this, Keyring::SECRET);

    QStringList ret;
    rnp_result_t res;
    rnp_input_t in = nullptr;
    char *json = nullptr;
    QJsonDocument keys;
    if ((res = rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from data." << res;
        goto out;
    }
    if ((res = rnp_import_keys(m_ffi, in, RNP_LOAD_SAVE_PERMISSIVE, &json))) {
        qCWarning(lcRnp) << "cannot import keys from data." << res;
        goto out;
    }
    keys = QJsonDocument::fromJson(json);
    for (const QJsonValue &key : keys.object()["keys"].toArray()) {
        
        qCDebug(lcRnp) << "import" << key.toObject()["fingerprint"];
    }
 out:
    if (in)
        rnp_input_destroy(in);
    if (json)
        rnp_buffer_destroy(json);
    return ret;    
}

QByteArray Rnp::sign(const QByteArray &data, const Rnp::Key key[], bool armor) const
{
    QByteArray ret;
    rnp_input_t in = nullptr;
    rnp_output_t out = nullptr;
    rnp_op_sign_t op = nullptr;
    rnp_result_t res;

    qCDebug(lcRnp) << "calling sign().";
    if ((res = rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from data." << res;
        goto out;
    }
    if ((res = rnp_output_to_memory(&out, 1024 * 1024))) {
        qCWarning(lcRnp) << "cannot create memory buffer for output." << res;
        goto out;
    }
    if ((res = rnp_op_sign_detached_create(&op, m_ffi, in, out))) {
        qCWarning(lcRnp) << "cannot create a sign operation." << res;
        goto out;
    }
    if ((res = rnp_op_sign_set_armor(op, armor))) {
        qCWarning(lcRnp) << "cannot set armor status." << res;
        goto out;
    }
    for (uint i = 0; key[i].isValid(); i++) {
        qCDebug(lcRnp) << "adding a key.";
        bool canSign;
        if ((res = rnp_key_allows_usage(key[i], "sign", &canSign)) || !canSign ) {
            qCWarning(lcRnp) << "key cannot sign." << res;
            goto out;
        }
        if ((res = rnp_op_sign_add_signature(op, key[i], nullptr))) {
            qCWarning(lcRnp) << "cannot add key for signature." << res;
            goto out;
        }
    }
    qCDebug(lcRnp) << "Starting signing operation.";
    uint8_t *buf;
    size_t len;
    if ((res = rnp_op_sign_execute(op))
        || (res = rnp_output_memory_get_buf(out, &buf, &len, false))) {
        qCWarning(lcRnp) << "cannot sign or retrieve output." << res;
        goto out;
    } else {
        ret = QByteArray((char*)buf, len);
    }
 out:
    if (in)
        rnp_input_destroy(in);
    if (out)
        rnp_output_destroy(out);
    if (op)
        rnp_op_sign_destroy(op);
    return ret;
}

static Rnp::Signature toSignature(rnp_ffi_t ffi, rnp_op_verify_signature_t vsig)
{
    rnp_result_t res;
    rnp_key_handle_t key = nullptr;
    if ((res = rnp_op_verify_signature_get_key(vsig, &key))) {
        if (res == RNP_ERROR_KEY_NOT_FOUND) {
            QString id, fp;
            rnp_signature_handle_t sig = nullptr;
            if (rnp_op_verify_signature_get_handle(vsig, &sig) == RNP_SUCCESS) {
                char *keyid = nullptr;
                if (rnp_signature_get_keyid(sig, &keyid) == RNP_SUCCESS) {
                    id = QString::fromLatin1(keyid);
                    rnp_buffer_destroy(keyid);
                }
                char *fprint = nullptr;
                if (rnp_signature_get_key_fprint(sig, &fprint) == RNP_SUCCESS) {
                    fp = QString::fromLatin1(fprint);
                    rnp_buffer_destroy(fprint);
                }
                rnp_signature_handle_destroy(sig);
            }
            qCDebug(lcRnp) << "key not found for signature" << id << fp;
            return Rnp::Signature(Rnp::Signature::KEY_NOT_FOUND, id, fp);
        } else {
            qCWarning(lcRnp) << "error retrieving key used for signature";
            return Rnp::Signature();
        }
    }

    QString fp;
    char *fprint = nullptr;
    if (rnp_key_get_fprint(key, &fprint) == RNP_SUCCESS) {
        fp = QString::fromLatin1(fprint);
        rnp_buffer_destroy(fprint);
    }
    QString id;
    bool primary = false;
    if (rnp_key_is_primary(key, &primary) == RNP_SUCCESS && primary) {
        char *keyid = nullptr;
        if (rnp_key_get_keyid(key, &keyid) == RNP_SUCCESS) {
            id = QString::fromLatin1(keyid);
            rnp_buffer_destroy(keyid);
        }
    } else {
        fprint = nullptr;
        rnp_key_handle_t pkey = nullptr;
        if (rnp_key_get_primary_fprint(key, &fprint) == RNP_SUCCESS
            && rnp_locate_key(ffi, "fingerprint", fprint, &pkey) == RNP_SUCCESS) {
            char *keyid = nullptr;
            if (rnp_key_get_keyid(key, &keyid) == RNP_SUCCESS) {
                id = QString::fromLatin1(keyid);
                rnp_buffer_destroy(keyid);
            }
        }
        if (fprint)
            rnp_buffer_destroy(fprint);
        if (pkey)
            rnp_key_handle_destroy(pkey);
    }
    QString fpp;
    if (rnp_key_get_primary_fprint(key, &fprint) == RNP_SUCCESS) {
        fp = QString::fromLatin1(fprint);
        rnp_buffer_destroy(fprint);
    }
    rnp_key_handle_destroy(key);

    qCDebug(lcRnp) << "found a signature" << fp << rnp_op_verify_signature_get_status(vsig);

    switch (rnp_op_verify_signature_get_status(vsig)) {
    case RNP_SUCCESS:
        return Rnp::Signature{Rnp::Signature::VALID, id, fp};
    case RNP_ERROR_SIGNATURE_EXPIRED:
        return Rnp::Signature{Rnp::Signature::EXPIRED, id, fp};
    case RNP_ERROR_KEY_NOT_FOUND:
        return Rnp::Signature{Rnp::Signature::KEY_NOT_FOUND, id, fp};
    case RNP_ERROR_SIGNATURE_INVALID:
        return Rnp::Signature{Rnp::Signature::INVALID, id, fp};
    default:
        return Rnp::Signature{Rnp::Signature::UNKNOWN, id, fp};
    }
}

QList<Rnp::Signature> Rnp::verify(const QByteArray &data, const QByteArray &signature) const
{
    QList<Signature> ret;
    rnp_input_t in = nullptr;
    rnp_input_t sig = nullptr;
    rnp_op_verify_t op = nullptr;
    rnp_result_t res;

    qCDebug(lcRnp) << "calling verify().";
    if ((res = rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from data." << res;
        goto out;
    }
    if ((res = rnp_input_from_memory(&sig, (const uint8_t*)signature.data(), signature.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from signature." << res;
        goto out;
    }
    if (!m_publicKeyring)
        m_publicKeyring = new Keyring(this, Keyring::PUBLIC);
    if ((res = rnp_op_verify_detached_create(&op, m_ffi, in, sig))) {
        qCWarning(lcRnp) << "cannot create a verify operation." << res;
        goto out;
    }
    qCDebug(lcRnp) << "Starting verification operation.";
    if ((res = rnp_op_verify_execute(op))) {
        qCWarning(lcRnp) << "cannot verify." << res;
    }
    size_t len;
    if (rnp_op_verify_get_signature_count(op, &len) == RNP_SUCCESS) {
        qCDebug(lcRnp) << "sign from" << len << "keys";
        for (size_t i = 0; i < len; i++) {
            rnp_op_verify_signature_t vsig = nullptr;
            if (rnp_op_verify_get_signature_at(op, i, &vsig) == RNP_SUCCESS) {
                ret.append(toSignature(m_ffi, vsig));
            }
        }
    }
 out:
    if (in)
        rnp_input_destroy(in);
    if (sig)
        rnp_input_destroy(sig);
    if (op)
        rnp_op_verify_destroy(op);
    return ret;
}

QByteArray Rnp::encrypt(const QByteArray &data, const Rnp::Key recipients[],
                        const Rnp::Key signers[], bool armor) const
{
    QByteArray ret;
    rnp_input_t in = nullptr;
    rnp_output_t out = nullptr;
    rnp_op_encrypt_t op = nullptr;
    rnp_result_t res;

    qCDebug(lcRnp) << "calling encrypt().";
    if ((res = rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from data." << res;
        goto out;
    }
    if ((res = rnp_output_to_memory(&out, 1024 * 1024 * 1024))) {
        qCWarning(lcRnp) << "cannot create memory buffer for output." << res;
        goto out;
    }
    if ((res = rnp_op_encrypt_create(&op, m_ffi, in, out))) {
        qCWarning(lcRnp) << "cannot create a sign operation." << res;
        goto out;
    }
    if ((res = rnp_op_encrypt_set_armor(op, armor))) {
        qCWarning(lcRnp) << "cannot set armor status." << res;
        goto out;
    }
    for (uint i = 0; recipients[i].isValid(); i++) {
        qCDebug(lcRnp) << "adding a key.";
        bool canEncrypt;
        if ((res = rnp_key_allows_usage(recipients[i], "encrypt", &canEncrypt)) || !canEncrypt ) {
            qCWarning(lcRnp) << "key cannot encrypt." << res;
            goto out;
        }
        if ((res = rnp_op_encrypt_add_recipient(op, recipients[i]))) {
            qCWarning(lcRnp) << "cannot add recipient key." << res;
            goto out;
        }
    }
    for (uint i = 0; signers[i].isValid(); i++) {
        qCDebug(lcRnp) << "adding a key.";
        bool canSign;
        if ((res = rnp_key_allows_usage(signers[i], "sign", &canSign)) || !canSign ) {
            qCWarning(lcRnp) << "key cannot sign." << res;
            goto out;
        }
        if ((res = rnp_op_encrypt_add_signature(op, signers[i], nullptr))) {
            qCWarning(lcRnp) << "cannot add signature key." << res;
            goto out;
        }
    }
    qCDebug(lcRnp) << "Starting encrypting operation.";
    uint8_t *buf;
    size_t len;
    if ((res = rnp_op_encrypt_execute(op))
        || (res = rnp_output_memory_get_buf(out, &buf, &len, false))) {
        qCWarning(lcRnp) << "cannot encrypt or retrieve output." << res;
        goto out;
    } else {
        ret = QByteArray((char*)buf, len);
    }
 out:
    if (in)
        rnp_input_destroy(in);
    if (out)
        rnp_output_destroy(out);
    if (op)
        rnp_op_encrypt_destroy(op);
    return ret;
}

QByteArray Rnp::decrypt(const QByteArray &data, QList<Rnp::Signature> *signers) const
{
    QByteArray ret;
    rnp_input_t in = nullptr;
    rnp_output_t out = nullptr;
    rnp_op_verify_t op = nullptr;
    rnp_result_t res;

    qCDebug(lcRnp) << "calling decrypt().";
    if ((res = rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false))) {
        qCWarning(lcRnp) << "cannot create memory buffer from data." << res;
        goto out;
    }
    if ((res = rnp_output_to_memory(&out, 1024 * 1024 * 1024))) {
        qCWarning(lcRnp) << "cannot create memory buffer for output." << res;
        goto out;
    }
    if (!m_secretKeyring)
        m_secretKeyring = new Keyring(this, Keyring::SECRET);
    qCDebug(lcRnp) << "Starting decrypting operation.";
    if (signers) {
        if ((res = rnp_op_verify_create(&op, m_ffi, in, out))) {
            qCWarning(lcRnp) << "cannot create a verify operation." << res;
            goto out;
        }
        uint8_t *buf;
        size_t len;
        if ((res = rnp_op_verify_execute(op))
            || (res = rnp_output_memory_get_buf(out, &buf, &len, false))) {
            qCWarning(lcRnp) << "cannot decrypt or retrieve output." << res;
            goto out;
        }
        ret = QByteArray((char*)buf, len);
        if (rnp_op_verify_get_signature_count(op, &len) == RNP_SUCCESS) {
            for (size_t i = 0; i < len; i++) {
                rnp_op_verify_signature_t vsig = nullptr;
                if (rnp_op_verify_get_signature_at(op, i, &vsig) == RNP_SUCCESS) {
                    signers->append(toSignature(m_ffi, vsig));
                }
            }
        }
    } else {
        uint8_t *buf;
        size_t len;
        if ((res = rnp_decrypt(m_ffi, in, out))
            || (res = rnp_output_memory_get_buf(out, &buf, &len, false))) {
            qCWarning(lcRnp) << "cannot decrypt or retrieve output." << res;
            goto out;
        }
        ret = QByteArray((char*)buf, len);
    }
 out:
    if (in)
        rnp_input_destroy(in);
    if (out)
        rnp_output_destroy(out);
    if (op)
        rnp_op_verify_destroy(op);
    return ret;
}

Rnp::Key::Key()
{
}

Rnp::Key::Key(const Rnp *rnp, const char *key, const QString &value)
{
    qCDebug(lcRnp) << "loading key" << key << value;
    rnp_result_t res;
    if ((res = rnp_locate_key(rnp->m_ffi, key, value.toLatin1().data(), &m_key)) != RNP_SUCCESS) {
        qCWarning(lcRnp) << "key not available." << res;
    }
    bool primary = false;
    char *fp = nullptr;
    if (m_key && rnp_key_is_primary(m_key, &primary) == RNP_SUCCESS && primary) {
        m_primary = m_key;
    } else if (m_key && rnp_key_get_primary_fprint(m_key, &fp) == RNP_SUCCESS) {
        rnp_locate_key(rnp->m_ffi, "fingerprint", fp, &m_primary);
        rnp_buffer_destroy(fp);
    }
}

Rnp::Key::Key(const Rnp::Key &key, size_t isub)
{
    qCDebug(lcRnp) << "loading subkey" << isub;
    if (key.m_primary) {
        rnp_key_get_subkey_at(key.m_primary, isub, &m_key);
        m_primary = key.m_primary;
    }
}

Rnp::Key::Key(Rnp::Key &&other)
{
    m_key = other.m_key;
    m_primary = other.m_primary;
    other.m_key = nullptr;
    other.m_primary = nullptr;
}

Rnp::Key& Rnp::Key::operator=(Rnp::Key &&other)
{
    m_key = other.m_key;
    m_primary = other.m_primary;
    other.m_key = nullptr;
    other.m_primary = nullptr;
    return *this;
}

Rnp::Key::~Key()
{
    if (m_key)
        rnp_key_handle_destroy(m_key);
}

bool Rnp::Key::isValid() const
{
    return m_key != nullptr;
}

QString Rnp::Key::keyid() const
{
    QString id;
    char *keyid = NULL;
    if (m_primary && rnp_key_get_keyid(m_primary, &keyid) == RNP_SUCCESS) {
        id = QString::fromLatin1(keyid);
        rnp_buffer_destroy(keyid);
    }
    return id;
}

QString Rnp::Key::fingerprint() const
{
    QString fp;
    char *fprint = nullptr;
    if (m_key && rnp_key_get_fprint(m_key, &fprint) == RNP_SUCCESS) {
        fp = QString::fromLatin1(fprint);
        rnp_buffer_destroy(fprint);
    }
    return fp;
}

QStringList Rnp::Key::fingerprints() const
{
    qCDebug(lcRnp) << "listing sub keys";
    QStringList fps;
    fps << fingerprint();

    size_t n = 0;
    if (m_key && m_key == m_primary
        && rnp_key_get_subkey_count(m_primary, &n) == RNP_SUCCESS) {
        qCDebug(lcRnp) << "found" << n << "subkey";
        for (size_t i = 0; i < n; i++) {
            rnp_key_handle_t sub = nullptr;
            char *fprint = nullptr;
            if (rnp_key_get_subkey_at(m_primary, i, &sub) == RNP_SUCCESS
                && rnp_key_get_fprint(sub, &fprint) == RNP_SUCCESS) {
                fps << QString::fromLatin1(fprint);
            }
            if (fprint)
                rnp_buffer_destroy(fprint);
            if (sub)
                rnp_key_handle_destroy(sub);
        }
    }
    return fps;
}

Rnp::Key Rnp::Key::subkey(const QString &fp) const
{
    size_t n = 0;
    if (m_key && rnp_key_get_subkey_count(m_key, &n) == RNP_SUCCESS) {
        for (size_t i = 0; i < n; i++) {
            Key sub = Key(*this, i);
            if (sub.fingerprint() == fp)
                return sub;
        }
    }
    return Key();
}

bool Rnp::Key::remove()
{
    int flags = RNP_KEY_REMOVE_PUBLIC;
    bool secret = false;
    if (rnp_key_have_secret(m_key, &secret) == RNP_SUCCESS && secret) {
        flags |= RNP_KEY_REMOVE_SECRET;
    }
    bool primary = false;
    if (rnp_key_is_primary(m_key, &primary) == RNP_SUCCESS && primary) {
        flags |= RNP_KEY_REMOVE_SUBKEYS;
    }

    if (rnp_key_remove(m_key, flags) == RNP_SUCCESS) {
        rnp_key_handle_destroy(m_key);
        m_key = nullptr;
    }

    return !isValid();
}

Sailfish::Crypto::Key Rnp::Key::toCryptoKey(const QString &pluginName) const
{
    Sailfish::Crypto::Key output;

    if (!isValid()) {
        return output;
    }

    output.setName(fingerprint());
    output.setCollectionName(keyid());
    output.setStoragePluginName(pluginName);
    output.setPublicKey(fingerprint().toLatin1());
    output.setPrivateKey("Rnp");

    QStringList emails;
    size_t n;
    if (rnp_key_get_uid_count(m_primary, &n) == RNP_SUCCESS) {
        for (size_t i = 0; i < n; i++) {
            rnp_uid_handle_t uid;
            if (rnp_key_get_uid_handle_at(m_primary, i, &uid) == RNP_SUCCESS) {
                uint32_t type;
                char *data = nullptr;
                if (rnp_uid_get_type(uid, &type) == RNP_SUCCESS
                    && type == RNP_USER_ID
                    && rnp_key_get_uid_at(m_primary, i, &data) == RNP_SUCCESS) {
                    // Fix: remove name from data.
                    emails << QString::fromUtf8(data);
                    rnp_buffer_destroy(data);
                }
            }
        }
    }
    output.setFilterData("User-Emails", emails.join(","));
    uint32_t expiration = 0;
    if (rnp_key_get_expiration(m_key, &expiration) == RNP_SUCCESS) {
        output.setFilterData("Expired", expiration ? "true" : "false");
        if (expiration) {
            output.setFilterData("Expire-Date",
                                 QDateTime::fromMSecsSinceEpoch(expiration).toString());
        }
    }
    uint32_t creation;
    if (rnp_key_get_creation(m_key, &creation) == RNP_SUCCESS
        && creation) {
        output.setFilterData("Creation-Date",
                              QDateTime::fromMSecsSinceEpoch(creation).toString());
    }
    output.setOrigin(Sailfish::Crypto::Key::OriginUnknown);
    if (rnp_key_get_subkey_count(m_primary, &n) == RNP_SUCCESS) {
        output.setSize(n);
    }
    char *algo = nullptr;
    if (rnp_key_get_alg(m_key, &algo) == RNP_SUCCESS) {
        if (!strcmp(algo, "RSA"))
            output.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmRsa);
        else if (!strcmp(algo, "DSA"))
            output.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmDsa);
        else
            output.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmUnknown);
        rnp_buffer_destroy(algo);
    }
    Sailfish::Crypto::CryptoManager::Operations op
        = Sailfish::Crypto::CryptoManager::OperationVerify
        | Sailfish::Crypto::CryptoManager::OperationDecrypt;
    bool allow;
    if (rnp_key_allows_usage(m_key, "encrypt", &allow) == RNP_SUCCESS
        && allow) {
        op |= Sailfish::Crypto::CryptoManager::OperationEncrypt;
    }
    if (rnp_key_allows_usage(m_key, "sign", &allow) == RNP_SUCCESS
        && allow) {
        op |= Sailfish::Crypto::CryptoManager::OperationSign;
    }
    output.setOperations(op);

    return output;
}

Rnp::Keyring::Keyring(const Rnp *rnp, Rnp::Keyring::Level level)
    : m_level(level)
    , m_rnp(rnp)
{
    qCDebug(lcRnp) << "New key ring" << rnp->m_format << level;

    const char *format = RNP_KEYSTORE_KBX;
    if (rnp->m_format == GPG_COMPAT) {
        format = RNP_KEYSTORE_GPG;
    }

    rnp_input_t keyin = nullptr;
    if ((level == PUBLIC
         && rnp_input_from_path(&keyin, rnp->m_publicKeyPath.toUtf8().data()))
        || (level == SECRET
            && rnp_input_from_path(&keyin, rnp->m_secretKeyPath.toUtf8().data()))) {
        qCWarning(lcRnp) << "cannot set keyring path as inputs.";
        return;
    }

    qCDebug(lcRnp) << "loading key ring" << format << rnp->m_publicKeyPath;
    uint32_t flags = level == PUBLIC ? RNP_LOAD_SAVE_PUBLIC_KEYS : RNP_LOAD_SAVE_SECRET_KEYS;
    rnp_result_t res = rnp_load_keys(rnp->m_ffi, format, keyin, flags);
    rnp_input_destroy(keyin);
    
    m_valid = (res == RNP_SUCCESS);
    if (!m_valid)
        qCWarning(lcRnp) << "cannot load keyring, error code:" << res;
}

Rnp::Keyring::~Keyring()
{
    if (m_modified) {
        const char *format = RNP_KEYSTORE_KBX;
        if (m_rnp->m_format == GPG_COMPAT) {
            format = RNP_KEYSTORE_GPG;
        }

        uint32_t flags = m_level == PUBLIC ? RNP_LOAD_SAVE_PUBLIC_KEYS : RNP_LOAD_SAVE_SECRET_KEYS;
        rnp_output_t keyout = nullptr;
        if ((m_level == PUBLIC
             && rnp_output_to_path(&keyout, m_rnp->m_publicKeyPath.toUtf8().data()) == RNP_SUCCESS)
            || (m_level == SECRET
                && rnp_output_to_path(&keyout, m_rnp->m_secretKeyPath.toUtf8().data()) == RNP_SUCCESS)) {
            rnp_save_keys(m_rnp->m_ffi, format, keyout, flags);
            rnp_output_destroy(keyout);
        }
    }
    if (m_valid) {
        uint32_t flags = m_level == PUBLIC ? RNP_KEY_UNLOAD_PUBLIC : RNP_KEY_UNLOAD_SECRET;
        rnp_unload_keys(m_rnp->m_ffi, flags);
    }
}

bool Rnp::Keyring::isValid() const
{
    return m_valid;
}

QString Rnp::Keyring::path() const
{
    return m_rnp->m_keyringPath;
}

QStringList Rnp::Keyring::keyids() const
{
    QStringList lst;
    rnp_identifier_iterator_t it = NULL;
    if (rnp_identifier_iterator_create(m_rnp->m_ffi, &it, "fingerprint")) {
        qCWarning(lcRnp) << "cannot create iterator on key ring";
        return lst;
    }
    const char *fp = nullptr;
    while (rnp_identifier_iterator_next(it, &fp) == RNP_SUCCESS && fp) {
        rnp_key_handle_t key = nullptr;
        char *id = nullptr;
        bool primary = false;
        qCDebug(lcRnp) << "found one key" << fp;
        if (rnp_locate_key(m_rnp->m_ffi, "fingerprint", fp, &key) == RNP_SUCCESS
            && rnp_key_is_primary(key, &primary) == RNP_SUCCESS && primary
            && rnp_key_get_keyid(key, &id) == RNP_SUCCESS) {
            lst.append(QString::fromLatin1(id));
        }
        if (id)
            rnp_buffer_destroy(id);
        if (key)
            rnp_key_handle_destroy(key);
    }
    rnp_identifier_iterator_destroy(it);

    return lst;
}

Rnp::Key Rnp::Keyring::key(const QString &keyid)
{
    return Key(m_rnp, "keyid", keyid);
}

Rnp::Key Rnp::Keyring::key(const Sailfish::Crypto::Key &key)
{
    Key k(m_rnp, "keyid", key.collectionName().toUpper());
    if (k.fingerprint() == key.name().toUpper())
        return k;
    else
        return k.subkey(key.name().toUpper());
}

Rnp::Key Rnp::Keyring::fromFingerprint(const QString &fp)
{
    return Key(m_rnp, "fingerprint", fp);
}

bool Rnp::Keyring::remove(Rnp::Key &key)
{
    bool res = key.remove();
    m_modified = res || m_modified;

    return res;
}
