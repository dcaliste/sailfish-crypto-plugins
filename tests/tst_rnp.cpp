/*
 * Copyright (C) 2026 Misja Hoebe.
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QPluginLoader>
#include <QTemporaryDir>

#include <signal.h>
#include <sys/resource.h>

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
        , m_rnp(Rnp::RNP_NATIVE)
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
    void missingKeyrings();
    void emptyKeyrings();
    void generatedKey();
    void gnupgHome();
    void subkeyReference();
    void removeKey();
    void decryptSigned_data();
    void decryptSigned();
    void verifySubkeySignature();
    void keyMetadata_data();
    void keyMetadata();
    void findSecrets_data();
    void findSecrets();
    void keyringSaved_data();
    void keyringSaved();
    void removalSaved_data();
    void removalSaved();
    void storedKey_data();
    void storedKey();
    void importAndStoreKey_data();
    void importAndStoreKey();
    void importFailure_data();
    void importFailure();
    void importCreatesHome();
    void capabilityFilters_data();
    void capabilityFilters();
    void keyAlgorithm_data();
    void keyAlgorithm();

private:
    QByteArray exportedKey(uint flags, QString *id, QStringList *fingerprints);
    bool saveKeyring(rnp_ffi_t ffi, const QString &fileName, const char *format, uint32_t flags);
    bool generateKey(QString *id, QStringList *fingerprints);
    QStringList savedFingerprints(const QString &fileName, uint32_t flags);

    QScopedPointer<QTemporaryDir> m_home;
};

// Each test has its own home: the plugin reads its keyrings from there.
void tst_Rnp::init()
{
    m_home.reset(new QTemporaryDir);
    QVERIFY(m_home->isValid());
    QVERIFY(QDir(m_home->path()).mkdir(QStringLiteral(".rnp")));
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

// Writes keyrings with a new key to ~/.rnp.
bool tst_Rnp::generateKey(QString *id, QStringList *fingerprints)
{
    rnp_ffi_t ffi = nullptr;
    if (rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX) != RNP_SUCCESS)
        return false;
    rnp_key_handle_t primary = nullptr;
    rnp_key_handle_t sub = nullptr;
    bool ok = rnp_generate_key_rsa(ffi, 2048, 2048, "Test <test@example.invalid>",
                                   nullptr, &primary) == RNP_SUCCESS
        && rnp_key_get_subkey_at(primary, 0, &sub) == RNP_SUCCESS;
    if (ok) {
        *id = keyid(primary);
        *fingerprints = QStringList() << fingerprint(primary) << fingerprint(sub);
        ok = saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                         RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS)
            && saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                           RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS);
    }
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
    return ok;
}

// A new key, exported from a keyring of its own.
QByteArray tst_Rnp::exportedKey(uint flags, QString *id, QStringList *fingerprints)
{
    QByteArray data;
    rnp_ffi_t ffi = nullptr;
    if (rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG) != RNP_SUCCESS)
        return data;
    rnp_key_handle_t primary = nullptr;
    rnp_key_handle_t sub = nullptr;
    rnp_output_t out = nullptr;
    uint8_t *buf = nullptr;
    size_t len = 0;
    if (rnp_generate_key_rsa(ffi, 2048, 2048, "Imported <imported@example.invalid>",
                             nullptr, &primary) == RNP_SUCCESS
        && rnp_key_get_subkey_at(primary, 0, &sub) == RNP_SUCCESS
        && rnp_output_to_memory(&out, 0) == RNP_SUCCESS
        && rnp_key_export(primary, out, flags | RNP_KEY_EXPORT_SUBKEYS) == RNP_SUCCESS
        && rnp_output_memory_get_buf(out, &buf, &len, false) == RNP_SUCCESS) {
        data = QByteArray((const char*)buf, len);
        *id = keyid(primary);
        *fingerprints = QStringList() << fingerprint(primary) << fingerprint(sub);
    }
    rnp_output_destroy(out);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
    return data;
}

// The fingerprints of the keys in a keyring file in ~/.rnp.
QStringList tst_Rnp::savedFingerprints(const QString &fileName, uint32_t flags)
{
    QStringList fps;
    rnp_ffi_t ffi = nullptr;
    rnp_input_t in = nullptr;
    rnp_identifier_iterator_t it = nullptr;
    const QString path = m_home->path() + QStringLiteral("/.rnp/") + fileName;
    if (rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX) == RNP_SUCCESS
        && rnp_input_from_path(&in, path.toLocal8Bit().constData()) == RNP_SUCCESS
        && rnp_load_keys(ffi, RNP_KEYSTORE_KBX, in, flags) == RNP_SUCCESS
        && rnp_identifier_iterator_create(ffi, &it, "fingerprint") == RNP_SUCCESS) {
        const char *fp = nullptr;
        while (rnp_identifier_iterator_next(it, &fp) == RNP_SUCCESS && fp)
            fps << QString::fromLatin1(fp);
    }
    rnp_identifier_iterator_destroy(it);
    rnp_input_destroy(in);
    rnp_ffi_destroy(ffi);
    return fps;
}

void tst_Rnp::loadPlugin()
{
    const QString path = QString::fromLocal8Bit(qgetenv("RNP_TEST_PLUGIN"));
    QVERIFY2(!path.isEmpty(), "RNP_TEST_PLUGIN is not set");

    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));

    QPluginLoader loader(path);
    QObject *plugin = loader.instance();
    QVERIFY2(plugin, qPrintable(loader.errorString()));

    Crypto::CryptoPlugin *crypto = qobject_cast<Crypto::CryptoPlugin*>(plugin);
    QVERIFY(crypto);
    QCOMPARE(crypto->name(), QStringLiteral("org.sailfishos.crypto.plugin.rnp.test"));

    Secrets::EncryptedStoragePlugin *storage
        = qobject_cast<Secrets::EncryptedStoragePlugin*>(plugin);
    QVERIFY(storage);
    QStringList names;
    QCOMPARE(storage->collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << id << QStringLiteral("import"));
}

void tst_Rnp::missingKeyrings()
{
    QVERIFY(QDir(m_home->path()).rmdir(QStringLiteral(".rnp")));

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << QStringLiteral("import"));
}

void tst_Rnp::emptyKeyrings()
{
    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
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

// A keyring in ~/.gnupg is not read.
void tst_Rnp::gnupgHome()
{
    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t primary = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, "Test <test@example.invalid>",
                                  nullptr, &primary),
             rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_destroy(primary);
    QVERIFY(QDir(m_home->path()).mkdir(QStringLiteral(".gnupg")));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".gnupg/pubring.gpg"),
                        RNP_KEYSTORE_GPG, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QCOMPARE(names, QStringList() << QStringLiteral("import"));
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

void tst_Rnp::decryptSigned_data()
{
    QTest::addColumn<uint>("removal");
    QTest::addColumn<int>("status");

    QTest::newRow("signer with public key") << uint(RNP_KEY_REMOVE_SECRET)
                                            << int(Rnp::Signature::VALID);
    QTest::newRow("unknown signer")
        << uint(RNP_KEY_REMOVE_PUBLIC | RNP_KEY_REMOVE_SECRET)
        << int(Rnp::Signature::KEY_NOT_FOUND);
}

// A message to a stored key, signed by a key whose secret part, or
// all of it, is removed from the keyrings.
void tst_Rnp::decryptSigned()
{
    QFETCH(uint, removal);
    QFETCH(int, status);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t recipient = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, "Recipient <recipient@example.invalid>",
                                  nullptr, &recipient),
             rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t signer = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 0, "Signer <signer@example.invalid>",
                                  nullptr, &signer),
             rnp_result_t(RNP_SUCCESS));

    const QByteArray plaintext("signed and encrypted");
    rnp_input_t in = nullptr;
    QCOMPARE(rnp_input_from_memory(&in, (const uint8_t*)plaintext.data(),
                                   plaintext.length(), false),
             rnp_result_t(RNP_SUCCESS));
    rnp_output_t out = nullptr;
    QCOMPARE(rnp_output_to_memory(&out, 0), rnp_result_t(RNP_SUCCESS));
    rnp_op_encrypt_t op = nullptr;
    QCOMPARE(rnp_op_encrypt_create(&op, ffi, in, out), rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_encrypt_add_recipient(op, recipient), rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_encrypt_add_signature(op, signer, nullptr), rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_encrypt_execute(op), rnp_result_t(RNP_SUCCESS));
    uint8_t *buf = nullptr;
    size_t len = 0;
    QCOMPARE(rnp_output_memory_get_buf(out, &buf, &len, false), rnp_result_t(RNP_SUCCESS));
    const QByteArray message((char*)buf, len);
    rnp_op_encrypt_destroy(op);
    rnp_output_destroy(out);
    rnp_input_destroy(in);

    const QString signerId = keyid(signer);
    QCOMPARE(rnp_key_remove(signer, removal), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_destroy(signer);
    rnp_key_handle_destroy(recipient);
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QList<Rnp::Signature> signatures;
    QCOMPARE(plugin.m_rnp.decrypt(message, &signatures), plaintext);
    QCOMPARE(signatures.size(), 1);
    QCOMPARE(int(signatures.at(0).status), status);
    QCOMPARE(signatures.at(0).keyid, signerId);
}

// A signature by a signing subkey, verified with a reference to its primary key.
void tst_Rnp::verifySubkeySignature()
{
    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t primary = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 0, "Signer <signer@example.invalid>",
                                  nullptr, &primary),
             rnp_result_t(RNP_SUCCESS));
    rnp_op_generate_t generate = nullptr;
    QCOMPARE(rnp_op_generate_subkey_create(&generate, ffi, primary, "RSA"),
             rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_generate_set_bits(generate, 2048), rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_generate_add_usage(generate, "sign"), rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_op_generate_execute(generate), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t sub = nullptr;
    QCOMPARE(rnp_op_generate_get_key(generate, &sub), rnp_result_t(RNP_SUCCESS));
    rnp_op_generate_destroy(generate);
    const QString id = keyid(primary);
    const QString primaryFingerprint = fingerprint(primary);
    const QString subFingerprint = fingerprint(sub);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    const QByteArray data("signed by a subkey");
    QByteArray signature;
    QCOMPARE(plugin.sign(data, Crypto::Key(subFingerprint, id, plugin.name()),
                         Crypto::CryptoManager::SignaturePaddingNone,
                         Crypto::CryptoManager::DigestUnknown,
                         QVariantMap(), &signature).code(),
             Crypto::Result::Succeeded);

    Crypto::CryptoManager::VerificationStatus status;
    QCOMPARE(plugin.verify(signature, data, Crypto::Key(primaryFingerprint, id, plugin.name()),
                           Crypto::CryptoManager::SignaturePaddingNone,
                           Crypto::CryptoManager::DigestUnknown,
                           QVariantMap(), &status).code(),
             Crypto::Result::Succeeded);
    QCOMPARE(int(status), int(Crypto::CryptoManager::VerificationSucceeded));
}

void tst_Rnp::keyMetadata_data()
{
    QTest::addColumn<uint>("creation");
    QTest::addColumn<uint>("expiration");
    QTest::addColumn<QString>("expired");

    QTest::newRow("expiring") << 0u << 365u * 24 * 3600 << QStringLiteral("false");
    QTest::newRow("not expiring") << 0u << 0u << QStringLiteral("false");
    // Created on 2020-01-01, valid for one day.
    QTest::newRow("expired") << 1577836800u << 24u * 3600 << QStringLiteral("true");
}

// The filter data of a primary key with two user IDs.
void tst_Rnp::keyMetadata()
{
    QFETCH(uint, creation);
    QFETCH(uint, expiration);
    QFETCH(QString, expired);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    if (creation)
        QCOMPARE(rnp_set_timestamp(ffi, creation), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t primary = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, "Test <test@example.invalid>",
                                  nullptr, &primary),
             rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_key_add_uid(primary, "other@example.invalid", nullptr, 0, 0, false),
             rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_key_set_expiration(primary, expiration), rnp_result_t(RNP_SUCCESS));
    uint32_t created = 0;
    QCOMPARE(rnp_key_get_creation(primary, &created), rnp_result_t(RNP_SUCCESS));
    const QString id = keyid(primary);
    rnp_key_handle_destroy(primary);
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    const Crypto::Key key = plugin.m_rnp.publicKeyring().key(id).toCryptoKey(plugin.name());
    QCOMPARE(key.filterData(QStringLiteral("Expired")), expired);
    QCOMPARE(key.filterData(QStringLiteral("Creation-Date")),
             QDateTime::fromTime_t(created).toString());
    QCOMPARE(key.filterData(QStringLiteral("Expire-Date")),
             expiration ? QDateTime::fromTime_t(created + expiration).toString() : QString());
    QCOMPARE(key.filterData(QStringLiteral("User-Emails")),
             QStringLiteral("test@example.invalid,other@example.invalid"));

    Secrets::Secret::FilterData filter;
    filter.insert(QStringLiteral("email"), QStringLiteral("test@example.invalid"));
    QVector<Secrets::Secret::Identifier> identifiers;
    QCOMPARE(plugin.findSecrets(id, filter, Secrets::StoragePlugin::OperatorAnd,
                                &identifiers).code(),
             Secrets::Result::Succeeded);
    bool found = false;
    for (const Secrets::Secret::Identifier &identifier : identifiers)
        found = found || identifier.collectionName() == id;
    QVERIFY(found);
}

void tst_Rnp::findSecrets_data()
{
    QTest::addColumn<bool>("all");

    QTest::newRow("named collection") << false;
    QTest::newRow("import") << true;
}

// Two keys; the search in the collection of the first finds the first,
// the search in "import" finds both.
void tst_Rnp::findSecrets()
{
    QFETCH(bool, all);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    QStringList ids;
    QStringList fingerprints;
    QStringList collections;
    const QStringList users = QStringList() << QStringLiteral("First <first@example.invalid>")
                                            << QStringLiteral("Second <second@example.invalid>");
    for (const QString &user : users) {
        rnp_key_handle_t primary = nullptr;
        QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, user.toUtf8().constData(),
                                      nullptr, &primary),
                 rnp_result_t(RNP_SUCCESS));
        rnp_key_handle_t sub = nullptr;
        QCOMPARE(rnp_key_get_subkey_at(primary, 0, &sub), rnp_result_t(RNP_SUCCESS));
        ids << keyid(primary);
        fingerprints << fingerprint(primary) << fingerprint(sub);
        collections << keyid(primary) << keyid(primary);
        rnp_key_handle_destroy(sub);
        rnp_key_handle_destroy(primary);
    }
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QVector<Secrets::Secret::Identifier> identifiers;
    QCOMPARE(plugin.findSecrets(all ? QStringLiteral("import") : ids.at(0),
                                Secrets::Secret::FilterData(),
                                Secrets::StoragePlugin::OperatorAnd, &identifiers).code(),
             Secrets::Result::Succeeded);
    QStringList names;
    QStringList collectionNames;
    for (const Secrets::Secret::Identifier &identifier : identifiers) {
        names << identifier.name();
        collectionNames << identifier.collectionName();
    }
    if (!all) {
        fingerprints = fingerprints.mid(0, 2);
        collections = collections.mid(0, 2);
    }
    QCOMPARE(names, fingerprints);
    QCOMPARE(collectionNames, collections);
}

void tst_Rnp::keyringSaved_data()
{
    QTest::addColumn<bool>("created");
    QTest::addColumn<bool>("failing");

    QTest::newRow("written") << false << false;
    QTest::newRow("created") << true << false;
    QTest::newRow("failed write") << false << true;
}

// A subkey is removed and the keyring saved. A new file is private; a
// write that fails, here on a file size limit, leaves the file as it was.
void tst_Rnp::keyringSaved()
{
    QFETCH(bool, created);
    QFETCH(bool, failing);

    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));
    const QString path = m_home->path() + QStringLiteral("/.rnp/pubring.kbx");

    struct rlimit limit;
    QCOMPARE(getrlimit(RLIMIT_FSIZE, &limit), 0);
    struct rlimit low = limit;
    low.rlim_cur = 256;
    void (*handler)(int) = signal(SIGXFSZ, SIG_IGN);
    {
        Rnp rnp(Rnp::RNP_NATIVE);
        Rnp::Key sub = rnp.publicKeyring().key(id).subkey(fingerprints.at(1));
        QVERIFY(rnp.publicKeyring().remove(sub));
        if (created)
            QVERIFY(QFile::remove(path));
        if (failing)
            QCOMPARE(setrlimit(RLIMIT_FSIZE, &low), 0);
    }
    QCOMPARE(setrlimit(RLIMIT_FSIZE, &limit), 0);
    signal(SIGXFSZ, handler);

    const QStringList saved = failing ? fingerprints : QStringList() << fingerprints.at(0);
    QCOMPARE(savedFingerprints(QStringLiteral("pubring.kbx"), RNP_LOAD_SAVE_PUBLIC_KEYS), saved);
    QCOMPARE(QFile::permissions(path), QFile::ReadOwner | QFile::WriteOwner
             | QFile::ReadUser | QFile::WriteUser);
}

void tst_Rnp::removalSaved_data()
{
    QTest::addColumn<bool>("subkey");

    QTest::newRow("key") << false;
    QTest::newRow("subkey") << true;
}

// The keyring files change while the plugin is still alive; the second key stays.
void tst_Rnp::removalSaved()
{
    QFETCH(bool, subkey);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    QString id;
    QStringList fingerprints;
    const QStringList users = QStringList() << QStringLiteral("First <first@example.invalid>")
                                            << QStringLiteral("Second <second@example.invalid>");
    for (const QString &user : users) {
        rnp_key_handle_t primary = nullptr;
        QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, user.toUtf8().constData(),
                                      nullptr, &primary),
                 rnp_result_t(RNP_SUCCESS));
        rnp_key_handle_t sub = nullptr;
        QCOMPARE(rnp_key_get_subkey_at(primary, 0, &sub), rnp_result_t(RNP_SUCCESS));
        if (id.isEmpty())
            id = keyid(primary);
        fingerprints << fingerprint(primary) << fingerprint(sub);
        rnp_key_handle_destroy(sub);
        rnp_key_handle_destroy(primary);
    }
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    QCOMPARE(plugin.removeSecret(id, subkey ? fingerprints.at(1) : QString()).code(),
             Secrets::Result::Succeeded);
    QStringList remaining = fingerprints.mid(2);
    if (subkey)
        remaining.prepend(fingerprints.at(0));
    QCOMPARE(savedFingerprints(QStringLiteral("pubring.kbx"), RNP_LOAD_SAVE_PUBLIC_KEYS),
             remaining);
    QCOMPARE(savedFingerprints(QStringLiteral("secring.kbx"), RNP_LOAD_SAVE_SECRET_KEYS),
             remaining);
}

void tst_Rnp::storedKey_data()
{
    QTest::addColumn<int>("index");
    QTest::addColumn<bool>("secret");
    QTest::addColumn<QString>("secretKeyring");
    QTest::addColumn<int>("errorCode");

    const QString kept = QStringLiteral("kept");
    QTest::newRow("primary") << 0 << false << kept << int(Crypto::Result::NoError);
    QTest::newRow("subkey") << 1 << false << kept << int(Crypto::Result::NoError);
    QTest::newRow("secret") << 0 << true << kept << int(Crypto::Result::NoError);
    QTest::newRow("no secret key") << 0 << true << QStringLiteral("removed")
                                   << int(Crypto::Result::InvalidKeyIdentifier);
    QTest::newRow("unreadable keyring") << 0 << true << QStringLiteral("unreadable")
                                        << int(Crypto::Result::StorageError);
    QTest::newRow("unknown") << -1 << false << kept
                             << int(Crypto::Result::InvalidKeyIdentifier);
}

// The public keyring is loaded first, as the daemon lists the
// collections when it starts; a key is then found without its
// secret part when the secret keyring is removed.
void tst_Rnp::storedKey()
{
    QFETCH(int, index);
    QFETCH(bool, secret);
    QFETCH(QString, secretKeyring);
    QFETCH(int, errorCode);

    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));
    QFile secring(m_home->path() + QStringLiteral("/.rnp/secring.kbx"));
    if (secretKeyring == QStringLiteral("removed")) {
        QVERIFY(secring.remove());
    } else if (secretKeyring == QStringLiteral("unreadable")) {
        QVERIFY(secring.open(QIODevice::WriteOnly));
        QCOMPARE(secring.write("not a keyring"), qint64(13));
        secring.close();
    }
    const QString fp = index < 0 ? QString(40, QLatin1Char('0')) : fingerprints.at(index);

    Plugin plugin;
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    Crypto::Key key;
    const Crypto::Result result
        = plugin.storedKey(Crypto::Key::Identifier(fp, id, plugin.name()),
                           secret ? Crypto::Key::SecretKeyData : Crypto::Key::PublicKeyData,
                           QVariantMap(), &key);
    QCOMPARE((int)result.errorCode(), errorCode);
    if (errorCode == Crypto::Result::NoError) {
        QCOMPARE(key.name(), fp);
        QCOMPARE(key.collectionName(), id);
        QCOMPARE(key.storagePluginName(), plugin.name());
    }
}

void tst_Rnp::importAndStoreKey_data()
{
    QTest::addColumn<uint>("flags");
    QTest::addColumn<int>("imports");

    QTest::newRow("public key") << uint(RNP_KEY_EXPORT_PUBLIC) << 1;
    QTest::newRow("secret key") << uint(RNP_KEY_EXPORT_SECRET) << 1;
    QTest::newRow("same key twice") << uint(RNP_KEY_EXPORT_SECRET) << 2;
}

// The keyring files hold the stored and the imported key while the
// plugin is still alive.
void tst_Rnp::importAndStoreKey()
{
    QFETCH(uint, flags);
    QFETCH(int, imports);

    QString id;
    QStringList stored;
    QVERIFY(generateKey(&id, &stored));
    QString importedId;
    QStringList imported;
    const QByteArray data = exportedKey(flags, &importedId, &imported);
    QVERIFY(!data.isEmpty());

    Plugin plugin;
    Crypto::Key key;
    for (int i = 0; i < imports; i++) {
        QCOMPARE(plugin.importAndStoreKey(data, Crypto::Key(), QByteArray(), QVariantMap(),
                                          &key).code(),
                 Crypto::Result::Succeeded);
    }
    QCOMPARE(key.name(), imported.at(0));
    QCOMPARE(key.collectionName(), importedId);
    QStringList names;
    QCOMPARE(plugin.collectionNames(&names).code(), Secrets::Result::Succeeded);
    QVERIFY(names.contains(importedId));

    QStringList pub = savedFingerprints(QStringLiteral("pubring.kbx"),
                                        RNP_LOAD_SAVE_PUBLIC_KEYS);
    pub.sort();
    QStringList expected = stored + imported;
    expected.sort();
    QCOMPARE(pub, expected);
    QStringList sec = savedFingerprints(QStringLiteral("secring.kbx"),
                                        RNP_LOAD_SAVE_SECRET_KEYS);
    sec.sort();
    if (flags != RNP_KEY_EXPORT_SECRET) {
        expected = stored;
        expected.sort();
    }
    QCOMPARE(sec, expected);
}

void tst_Rnp::importFailure_data()
{
    QTest::addColumn<bool>("keyData");
    QTest::addColumn<bool>("readable");
    QTest::addColumn<int>("errorCode");

    QTest::newRow("no key") << false << true
                            << int(Crypto::Result::CryptoPluginKeyImportError);
    QTest::newRow("unreadable keyring") << true << false
                                        << int(Crypto::Result::StorageError);
}

// A failed import leaves the keyring file as it was.
void tst_Rnp::importFailure()
{
    QFETCH(bool, keyData);
    QFETCH(bool, readable);
    QFETCH(int, errorCode);

    QString id;
    QStringList fingerprints;
    QVERIFY(generateKey(&id, &fingerprints));
    QFile pubring(m_home->path() + QStringLiteral("/.rnp/pubring.kbx"));
    if (!readable) {
        QVERIFY(pubring.open(QIODevice::WriteOnly));
        QCOMPARE(pubring.write("not a keyring"), qint64(13));
        pubring.close();
    }
    QVERIFY(pubring.open(QIODevice::ReadOnly));
    const QByteArray before = pubring.readAll();
    pubring.close();
    QString importedId;
    QStringList imported;
    const QByteArray data = keyData
        ? exportedKey(RNP_KEY_EXPORT_PUBLIC, &importedId, &imported)
        : QByteArray("not a key");

    Plugin plugin;
    Crypto::Key key;
    const Crypto::Result result
        = plugin.importAndStoreKey(data, Crypto::Key(), QByteArray(), QVariantMap(), &key);
    QCOMPARE((int)result.errorCode(), errorCode);
    QVERIFY(pubring.open(QIODevice::ReadOnly));
    QCOMPARE(pubring.readAll(), before);
}

// A first import creates the missing key home, owner-only.
void tst_Rnp::importCreatesHome()
{
    QVERIFY(QDir(m_home->path()).rmdir(QStringLiteral(".rnp")));
    QString importedId;
    QStringList imported;
    const QByteArray data = exportedKey(RNP_KEY_EXPORT_SECRET, &importedId, &imported);
    QVERIFY(!data.isEmpty());

    Plugin plugin;
    Crypto::Key key;
    QCOMPARE(plugin.importAndStoreKey(data, Crypto::Key(), QByteArray(), QVariantMap(),
                                      &key).code(),
             Crypto::Result::Succeeded);
    QCOMPARE(QFileInfo(m_home->path() + QStringLiteral("/.rnp")).permissions(),
             QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner
             | QFile::ReadUser | QFile::WriteUser | QFile::ExeUser);
    QStringList pub = savedFingerprints(QStringLiteral("pubring.kbx"),
                                        RNP_LOAD_SAVE_PUBLIC_KEYS);
    pub.sort();
    imported.sort();
    QCOMPARE(pub, imported);
}

void tst_Rnp::capabilityFilters_data()
{
    QTest::addColumn<QString>("filter");
    QTest::addColumn<QString>("value");
    QTest::addColumn<QStringList>("expected");

    QTest::newRow("canSign true") << QStringLiteral("canSign") << QStringLiteral("true")
                                  << (QStringList() << "rsa" << "ed25519");
    QTest::newRow("canSign false") << QStringLiteral("canSign") << QStringLiteral("false")
                                   << (QStringList() << "rsa sub" << "cv25519"
                                       << "contact" << "contact sub");
    QTest::newRow("canEncrypt true") << QStringLiteral("canEncrypt") << QStringLiteral("true")
                                     << (QStringList() << "rsa sub" << "cv25519"
                                         << "contact sub");
    QTest::newRow("canEncrypt false") << QStringLiteral("canEncrypt") << QStringLiteral("false")
                                      << (QStringList() << "rsa" << "ed25519" << "contact");
}

// Own RSA and Ed25519 keys, and the public key of a contact.
void tst_Rnp::capabilityFilters()
{
    QFETCH(QString, filter);
    QFETCH(QString, value);
    QFETCH(QStringList, expected);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t rsa = nullptr;
    QCOMPARE(rnp_generate_key_rsa(ffi, 2048, 2048, "RSA <rsa@example.invalid>", nullptr, &rsa),
             rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t ed25519 = nullptr;
    QCOMPARE(rnp_generate_key_25519(ffi, "Ed25519 <ed25519@example.invalid>", nullptr,
                                    &ed25519),
             rnp_result_t(RNP_SUCCESS));
    QString contactId;
    QStringList contact;
    const QByteArray data = exportedKey(RNP_KEY_EXPORT_PUBLIC, &contactId, &contact);
    QVERIFY(!data.isEmpty());
    rnp_input_t in = nullptr;
    QCOMPARE(rnp_input_from_memory(&in, (const uint8_t*)data.data(), data.length(), false),
             rnp_result_t(RNP_SUCCESS));
    QCOMPARE(rnp_import_keys(ffi, in, RNP_LOAD_SAVE_PUBLIC_KEYS, nullptr),
             rnp_result_t(RNP_SUCCESS));
    rnp_input_destroy(in);

    QMap<QString, QString> fingerprints;
    rnp_key_handle_t sub = nullptr;
    fingerprints.insert(QStringLiteral("rsa"), fingerprint(rsa));
    QCOMPARE(rnp_key_get_subkey_at(rsa, 0, &sub), rnp_result_t(RNP_SUCCESS));
    fingerprints.insert(QStringLiteral("rsa sub"), fingerprint(sub));
    rnp_key_handle_destroy(sub);
    fingerprints.insert(QStringLiteral("ed25519"), fingerprint(ed25519));
    QCOMPARE(rnp_key_get_subkey_at(ed25519, 0, &sub), rnp_result_t(RNP_SUCCESS));
    fingerprints.insert(QStringLiteral("cv25519"), fingerprint(sub));
    rnp_key_handle_destroy(sub);
    fingerprints.insert(QStringLiteral("contact"), contact.at(0));
    fingerprints.insert(QStringLiteral("contact sub"), contact.at(1));
    rnp_key_handle_destroy(ed25519);
    rnp_key_handle_destroy(rsa);
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/secring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_SECRET_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    Secrets::Secret::FilterData filterData;
    filterData.insert(filter, value);
    QVector<Secrets::Secret::Identifier> identifiers;
    QCOMPARE(plugin.findSecrets(QStringLiteral("import"), filterData,
                                Secrets::StoragePlugin::OperatorAnd, &identifiers).code(),
             Secrets::Result::Succeeded);
    QStringList found;
    for (const Secrets::Secret::Identifier &identifier : identifiers)
        found << identifier.name();
    found.sort();
    QStringList wanted;
    for (const QString &label : expected)
        wanted << fingerprints.value(label);
    wanted.sort();
    QCOMPARE(found, wanted);
}

void tst_Rnp::keyAlgorithm_data()
{
    QTest::addColumn<QByteArray>("primaryAlg");
    QTest::addColumn<QByteArray>("subkeyAlg");
    QTest::addColumn<QByteArray>("primaryCurve");
    QTest::addColumn<QByteArray>("subkeyCurve");
    QTest::addColumn<int>("primaryAlgorithm");
    QTest::addColumn<int>("subkeyAlgorithm");

    QTest::newRow("RSA") << QByteArray("RSA") << QByteArray("RSA")
                         << QByteArray() << QByteArray()
                         << int(Crypto::CryptoManager::AlgorithmRsa)
                         << int(Crypto::CryptoManager::AlgorithmRsa);
    QTest::newRow("Ed25519") << QByteArray("EDDSA") << QByteArray("ECDH")
                             << QByteArray() << QByteArray("Curve25519")
                             << int(Crypto::CryptoManager::AlgorithmEdDsa)
                             << int(Crypto::CryptoManager::AlgorithmEcDh);
    QTest::newRow("NIST P-256") << QByteArray("ECDSA") << QByteArray("ECDH")
                                << QByteArray("NIST P-256") << QByteArray("NIST P-256")
                                << int(Crypto::CryptoManager::AlgorithmEcDsa)
                                << int(Crypto::CryptoManager::AlgorithmEcDh);
}

void tst_Rnp::keyAlgorithm()
{
    QFETCH(QByteArray, primaryAlg);
    QFETCH(QByteArray, subkeyAlg);
    QFETCH(QByteArray, primaryCurve);
    QFETCH(QByteArray, subkeyCurve);
    QFETCH(int, primaryAlgorithm);
    QFETCH(int, subkeyAlgorithm);

    rnp_ffi_t ffi = nullptr;
    QCOMPARE(rnp_ffi_create(&ffi, RNP_KEYSTORE_KBX, RNP_KEYSTORE_KBX), rnp_result_t(RNP_SUCCESS));
    const uint32_t bits = primaryAlg == "RSA" ? 2048 : 0;
    rnp_key_handle_t primary = nullptr;
    QCOMPARE(rnp_generate_key_ex(ffi, primaryAlg.constData(), subkeyAlg.constData(), bits, bits,
                                 primaryCurve.isEmpty() ? nullptr : primaryCurve.constData(),
                                 subkeyCurve.isEmpty() ? nullptr : subkeyCurve.constData(),
                                 "Test <test@example.invalid>", nullptr, &primary),
             rnp_result_t(RNP_SUCCESS));
    rnp_key_handle_t sub = nullptr;
    QCOMPARE(rnp_key_get_subkey_at(primary, 0, &sub), rnp_result_t(RNP_SUCCESS));
    const QString primaryFp = fingerprint(primary);
    const QString subkeyFp = fingerprint(sub);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    QVERIFY(saveKeyring(ffi, QStringLiteral(".rnp/pubring.kbx"),
                        RNP_KEYSTORE_KBX, RNP_LOAD_SAVE_PUBLIC_KEYS));
    rnp_ffi_destroy(ffi);

    Plugin plugin;
    const Crypto::Key key = plugin.m_rnp.publicKeyring().fromFingerprint(primaryFp)
        .toCryptoKey(plugin.name());
    QCOMPARE((int)key.algorithm(), primaryAlgorithm);
    const Crypto::Key subkey = plugin.m_rnp.publicKeyring().fromFingerprint(subkeyFp)
        .toCryptoKey(plugin.name());
    QCOMPARE((int)subkey.algorithm(), subkeyAlgorithm);
}

QTEST_GUILESS_MAIN(tst_Rnp)
#include "tst_rnp.moc"
