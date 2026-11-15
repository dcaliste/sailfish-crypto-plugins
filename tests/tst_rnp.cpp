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

private:
    bool saveKeyring(rnp_ffi_t ffi, const QString &fileName, uint32_t flags);

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

bool tst_Rnp::saveKeyring(rnp_ffi_t ffi, const QString &fileName, uint32_t flags)
{
    const QString path = m_home->path() + QStringLiteral("/.gnupg/") + fileName;
    rnp_output_t out = nullptr;
    if (rnp_output_to_path(&out, path.toLocal8Bit().constData()) != RNP_SUCCESS)
        return false;
    const rnp_result_t res = rnp_save_keys(ffi, RNP_KEYSTORE_GPG, out, flags);
    rnp_output_destroy(out);
    return res == RNP_SUCCESS;
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
    QVERIFY(saveKeyring(ffi, QStringLiteral("pubring.gpg"), RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral("secring.gpg"), RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << QStringLiteral("import"));
}

void tst_Rnp::generatedKey()
{
    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t primary = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, "Test <test@example.invalid>",
                                  nullptr, &primary),
             rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t sub = nullptr;
    QCOMPARE(rnp_key_get_subkey_at(primary, 0, &sub), rnp_result_t(RNP_SUCCESS));
    const QString id = keyid(primary);
    const QStringList fingerprints = QStringList() << fingerprint(primary) << fingerprint(sub);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    QVERIFY(saveKeyring(ffi, QStringLiteral("pubring.gpg"), RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral("secring.gpg"), RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << id << QStringLiteral("import"));

    QStringList secrets;
    QCOMPARE(plugin.secretNames(id, &secrets).code(), Secrets::Result::Succeeded);
    QCOMPARE(secrets, fingerprints);
}

QTEST_GUILESS_MAIN(tst_Rnp)
#include "tst_rnp.moc"
