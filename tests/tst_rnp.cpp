/*
 * Copyright (C) 2026 Misja Hoebe.
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QPluginLoader>
#include <QTemporaryDir>

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

#include "rnp_p.h"
#include "rnpffi.h"
#include "rnpkeys.h"

using namespace Sailfish;

// The plugin classes without the QObject of plugin.cpp, to get
// a new instance for each test.
class Plugin
    : public RnpFfi
    , public RnpKeys
{
public:
    Plugin()
        : RnpFfi(&m_rnp)
        , RnpKeys(&m_rnp)
        , m_rnp(Rnp::GPG_COMPAT)
    {
    }

    QString name() const override {
        return QStringLiteral("org.sailfishos.crypto.plugin.rnp.test");
    }

    QString displayName() const override {
        return QStringLiteral("RNP");
    }

    int version() const override {
        return 000001;
    }

    Rnp m_rnp;
};

static QString fingerprint(rnp_key_handle_t key)
{
    QString fp;
    char *fprint = nullptr;
    if (rnp_key_get_fprint(key, &fprint) == RNP_SUCCESS) {
        fp = QString::fromLatin1(fprint);
        rnp_buffer_destroy(fprint);
    }
    return fp;
}

static QString keyid(rnp_key_handle_t key)
{
    QString id;
    char *value = nullptr;
    if (rnp_key_get_keyid(key, &value) == RNP_SUCCESS) {
        id = QString::fromLatin1(value);
        rnp_buffer_destroy(value);
    }
    return id;
}

class tst_Rnp : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();

    void loadPlugin();
    void emptyKeyrings();
    void generatedKey();
    void subkeyReference();
    void removeKey();

private:
    bool saveKeyring(rnp_ffi_t ffi, const QString &fileName, const char *format, uint32_t flags);
    bool generateKey(QString *id, QStringList *fingerprints);

    QScopedPointer<QTemporaryDir> m_home;
};

// Each test has its own home: the plugin reads its keyrings from there.
void tst_Rnp::init()
{
    m_home.reset(new QTemporaryDir);
    QVERIFY(m_home->isValid());
    QVERIFY(QDir(m_home->path()).mkdir(QStringLiteral(".gnupg")));
    qputenv("HOME", m_home->path().toLocal8Bit());
}

void tst_Rnp::cleanup()
{
    m_home.reset();
}

bool tst_Rnp::saveKeyring(rnp_ffi_t ffi, const QString &fileName, const char *format,
                          uint32_t flags)
{
    const QString path = m_home->path() + QLatin1Char('/') + fileName;
    rnp_output_t out = nullptr;
    if (rnp_output_to_path(&out, path.toLocal8Bit().constData()) != RNP_SUCCESS)
        return false;
    const rnp_result_t res = rnp_save_keys(ffi, format, out, flags);
    rnp_output_destroy(out);
    return res == RNP_SUCCESS;
}

// Writes keyrings with a new key to ~/.gnupg.
bool tst_Rnp::generateKey(QString *id, QStringList *fingerprints)
{
    rnp_ffi_t ffi = nullptr;
    if (rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG) != RNP_SUCCESS)
        return false;
    rnp_key_handle_t primary = nullptr;
    rnp_key_handle_t sub = nullptr;
    bool ok = rnp_generate_key_rsa(ffi, 2048, 2048, "Test <test@example.invalid>",
                                   nullptr, &primary) == RNP_SUCCESS
        && rnp_key_get_subkey_at(primary, 0, &sub) == RNP_SUCCESS;
    if (ok) {
        *id = keyid(primary);
        *fingerprints = QStringList() << fingerprint(primary) << fingerprint(sub);
        ok = saveKeyring(ffi, QStringLiteral(".gnupg/pubring.gpg"),
                         RNP_KEYSTORE_GPG, RNP_LOAD_SAVE_PUBLIC_KEYS)
            && saveKeyring(ffi, QStringLiteral(".gnupg/secring.gpg"),
                           RNP_KEYSTORE_GPG, RNP_LOAD_SAVE_SECRET_KEYS);
    }
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
    return ok;
}

void tst_Rnp::loadPlugin()
{
    const QString path = QString::fromLocal8Bit(qgetenv("RNP_TEST_PLUGIN"));
    QVERIFY2(!path.isEmpty(), "RNP_TEST_PLUGIN is not set");

    QPluginLoader loader(path);
    QObject *plugin = loader.instance();
    QVERIFY2(plugin, qPrintable(loader.errorString()));

    Crypto::CryptoPlugin *crypto = qobject_cast<Crypto::CryptoPlugin*>(plugin);
    QVERIFY(crypto);
    QCOMPARE(crypto->name(), QStringLiteral("org.sailfishos.crypto.plugin.rnp.test"));
    QVERIFY(qobject_cast<Secrets::EncryptedStoragePlugin*>(plugin));
}

void tst_Rnp::emptyKeyrings()
{
    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG), rnp_result_t(RNP_SUCCESS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".gnupg/pubring.gpg"),
                        RNP_KEYSTORE_GPG, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".gnupg/secring.gpg"),
                        RNP_KEYSTORE_GPG, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << QStringLiteral("import"));
}

void tst_Rnp::generatedKey()
{
    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << id << QStringLiteral("import"));

    QStringList secrets;
    QCOMPARE(plugin.secretNames(id, &secrets).code(), Secrets::Result::Succeeded);
    QCOMPARE(secrets, fingerprints);
}

void tst_Rnp::subkeyReference()
{
    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));

    Plugin plugin;
    const Crypto::Key reference(fingerprints.at(1), id, plugin.name());
    Rnp::Key key = plugin.m_rnp.publicKeyring().key(id);
    key = plugin.m_rnp.publicKeyring().key(reference);
    QCOMPARE(key.fingerprint(), fingerprints.at(1));
    QCOMPARE(key.keyid(), id);
}

void tst_Rnp::removeKey()
{
    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));

    Plugin plugin;
    QCOMPARE(plugin.removeSecret(id, fingerprints.at(1)).code(), Secrets::Result::Succeeded);
    QStringList secrets;
    QCOMPARE(plugin.secretNames(id, &secrets).code(), Secrets::Result::Succeeded);
    QCOMPARE(secrets, QStringList() << fingerprints.at(0));

    QCOMPARE(plugin.removeSecret(id, QString()).code(), Secrets::Result::Succeeded);
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << QStringLiteral("import"));
}

QTEST_GUILESS_MAIN(tst_Rnp)
#include "tst_rnp.moc"
