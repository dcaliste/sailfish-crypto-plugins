/*
 * Copyright (C) 2026 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef RNP_P_H
#define RNP_P_H

#include <rnp/rnp.h>
#include <Crypto/key.h>

#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcRnp)

class Q_DECL_EXPORT Rnp
{
 public:
    enum Format {
        RNP_NATIVE,
        GPG_COMPAT
    };

    Rnp(Format format = RNP_NATIVE);
    ~Rnp();

    class Key
    {
    public:
        Key();
        Key(const Rnp *rnp, const char *key, const QString &value);
        Key(const Key &key, size_t isub);
        Key(const Key &) = delete;
        Key(Key &&other);
        Key& operator=(const Key &) = delete;
        Key& operator=(Key &&other);
        operator rnp_key_handle_t() const
        {
            return m_key;
        }
        ~Key();

        bool isValid() const;
        QString keyid() const;
        QString fingerprint() const;
        QStringList fingerprints() const;
        Key subkey(const QString &fp) const;
        bool remove();
        Sailfish::Crypto::Key toCryptoKey(const QString &pluginName) const;
    private:
        rnp_key_handle_t m_key = nullptr;
        rnp_key_handle_t m_primary = nullptr;
    };

    class Keyring
    {
    public:
        enum Level {
            PUBLIC,
            SECRET
        };
        Keyring(const Rnp *rnp, Level level = PUBLIC);
        ~Keyring();

        bool isValid() const;
        QString path() const;
        QStringList keyids() const;
        Key key(const QString &keyid);
        Key key(const Sailfish::Crypto::Key &key);
        Key fromFingerprint(const QString &fp);
        bool remove(Key &key);
    private:
        bool m_valid = false;
        bool m_modified = false;
        Level m_level;
        const Rnp *m_rnp;
    };

    struct Signature
    {
        enum Status {
            VALID,
            EXPIRED,
            KEY_NOT_FOUND,
            INVALID,
            UNKNOWN
        };
        Signature() {}
        Signature(Status st, const QString &id, const QString &fp)
            : status(st), keyid(id), fingerprint(fp) {}
        Status status = UNKNOWN;
        QString keyid, fingerprint;
    };

    Keyring& publicKeyring() const;
    Keyring& secretKeyring() const;

    QStringList importKeys(const QByteArray &data);

    QByteArray sign(const QByteArray &data, const Key key[], bool armor) const;
    QList<Signature> verify(const QByteArray &data, const QByteArray &signature) const;
    QByteArray encrypt(const QByteArray &data, const Key recipients[],
                       const Key signers[], bool armor) const;
    QByteArray decrypt(const QByteArray &data, QList<Signature> *signers = nullptr) const;

 private:
    Format m_format;
    rnp_ffi_t m_ffi = nullptr;
    QString m_keyringPath;
    QString m_publicKeyPath;
    QString m_secretKeyPath;
    mutable Keyring *m_publicKeyring = nullptr;
    mutable Keyring *m_secretKeyring = nullptr;
};

#endif
