/*
 * Copyright (C) 2026 Misja Hoebe.
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QElapsedTimer>
#include <QProcess>
#include <QTemporaryDir>

#include <rnp/rnp.h>
#include <rnp/rnp_err.h>

#include <Crypto/cryptomanager.h>
#include <Crypto/importstoredkeyrequest.h>
#include <Crypto/storedkeyrequest.h>
#include <Crypto/storedkeyidentifiersrequest.h>
#include <Crypto/signrequest.h>
#include <Crypto/verifyrequest.h>
#include <Crypto/encryptrequest.h>
#include <Crypto/decryptrequest.h>
#include <Crypto/key.h>
#include <Secrets/secretmanager.h>
#include <Secrets/deletecollectionrequest.h>

using namespace Sailfish;

#define RNP_PLUGIN QStringLiteral("org.sailfishos.crypto.plugin.rnp.test")
#define DISCOVERY QStringLiteral("org.sailfishos.secrets.daemon.discovery")
#define TIMEOUT 60000

// sailfishsecretsd in test mode, in a home of its own: the plugin
// writes the keyrings of that home, never the user's.
class tst_RnpPlugin : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();

    void importUseRemove_data();
    void importUseRemove();

private:
    bool startDaemon();
    bool stopDaemon();
    QByteArray exportedKey(bool ed25519, QString *id, QStringList *fingerprints);
    QStringList savedFingerprints(const QString &fileName, uint32_t flags);

    QScopedPointer<QTemporaryDir> m_home;
    QScopedPointer<QProcess> m_daemon;
};

static bool discoveryRegistered()
{
    return QDBusConnection::sessionBus().interface()->isServiceRegistered(DISCOVERY);
}

void tst_RnpPlugin::initTestCase()
{
    QVERIFY2(QDBusConnection::sessionBus().isConnected(), "no session bus");
    QVERIFY2(!discoveryRegistered(),
             "a secrets daemon is on this bus, run the test under dbus-run-session");
    QVERIFY(QFile::exists(QStringLiteral("/usr/bin/sailfishsecretsd")));

    m_home.reset(new QTemporaryDir);
    QVERIFY(m_home->isValid());
    qputenv("HOME", m_home->path().toLocal8Bit());
    qputenv("XDG_RUNTIME_DIR", m_home->path().toLocal8Bit());
    qunsetenv("XDG_DATA_HOME");
    QVERIFY(startDaemon());
}

void tst_RnpPlugin::cleanupTestCase()
{
    if (m_daemon)
        stopDaemon();
    m_home.reset();
}

// The test plugin is found in the plugin directories of the daemon,
// or next to the file named by RNP_TEST_PLUGIN in a build tree.
bool tst_RnpPlugin::startDaemon()
{
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QString plugin = QString::fromLocal8Bit(qgetenv("RNP_TEST_PLUGIN"));
    if (!plugin.isEmpty())
        env.insert(QStringLiteral("QT_PLUGIN_PATH"), QFileInfo(plugin).absolutePath());
    m_daemon.reset(new QProcess);
    m_daemon->setProcessEnvironment(env);
    m_daemon->setProcessChannelMode(QProcess::ForwardedChannels);
    m_daemon->start(QStringLiteral("/usr/bin/sailfishsecretsd"),
                    QStringList() << QStringLiteral("--test"));
    if (!m_daemon->waitForStarted())
        return false;
    // The daemon registers its discovery names before it listens on
    // its socket; the test waits until a connection to it succeeds.
    const QString address = QStringLiteral("unix:path=%1/sailfishsecretsd/p2pSocket")
        .arg(m_home->path());
    QElapsedTimer timer;
    timer.start();
    bool listening = false;
    while (!listening && timer.elapsed() < TIMEOUT) {
        listening = QDBusConnection::connectToPeer(address, QStringLiteral("probe"))
            .isConnected();
        QDBusConnection::disconnectFromPeer(QStringLiteral("probe"));
        if (!listening)
            QTest::qWait(100);
    }
    return listening && discoveryRegistered();
}

bool tst_RnpPlugin::stopDaemon()
{
    m_daemon->terminate();
    const bool stopped = m_daemon->waitForFinished(TIMEOUT);
    m_daemon.reset();
    QElapsedTimer timer;
    timer.start();
    while (discoveryRegistered() && timer.elapsed() < TIMEOUT)
        QTest::qWait(100);
    // The connection of the old managers is deleted later; a new
    // manager would otherwise be given that connection.
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    return stopped && !discoveryRegistered();
}

// A new key without passphrase, exported with its secret keys.
QByteArray tst_RnpPlugin::exportedKey(bool ed25519, QString *id, QStringList *fingerprints)
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
    char *value = nullptr;
    const rnp_result_t res = ed25519
        ? rnp_generate_key_25519(ffi, "Ed25519 <ed25519@example.invalid>", nullptr, &primary)
        : rnp_generate_key_rsa(ffi, 2048, 2048, "RSA <rsa@example.invalid>", nullptr, &primary);
    if (res == RNP_SUCCESS
        && rnp_key_get_subkey_at(primary, 0, &sub) == RNP_SUCCESS
        && rnp_output_to_memory(&out, 0) == RNP_SUCCESS
        && rnp_key_export(primary, out, RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS)
           == RNP_SUCCESS
        && rnp_output_memory_get_buf(out, &buf, &len, false) == RNP_SUCCESS) {
        data = QByteArray((const char*)buf, len);
        if (rnp_key_get_keyid(primary, &value) == RNP_SUCCESS) {
            *id = QString::fromLatin1(value);
            rnp_buffer_destroy(value);
        }
        if (rnp_key_get_fprint(primary, &value) == RNP_SUCCESS) {
            *fingerprints << QString::fromLatin1(value);
            rnp_buffer_destroy(value);
        }
        if (rnp_key_get_fprint(sub, &value) == RNP_SUCCESS) {
            *fingerprints << QString::fromLatin1(value);
            rnp_buffer_destroy(value);
        }
    }
    rnp_output_destroy(out);
    rnp_key_handle_destroy(sub);
    rnp_key_handle_destroy(primary);
    rnp_ffi_destroy(ffi);
    return data;
}

// The fingerprints of the keys in a keyring file in ~/.gnupg.
QStringList tst_RnpPlugin::savedFingerprints(const QString &fileName, uint32_t flags)
{
    QStringList fps;
    rnp_ffi_t ffi = nullptr;
    rnp_input_t in = nullptr;
    rnp_identifier_iterator_t it = nullptr;
    const QString path = m_home->path() + QStringLiteral("/.gnupg/") + fileName;
    if (rnp_ffi_create(&ffi, RNP_KEYSTORE_GPG, RNP_KEYSTORE_GPG) == RNP_SUCCESS
        && rnp_input_from_path(&in, path.toLocal8Bit().constData()) == RNP_SUCCESS
        && rnp_load_keys(ffi, RNP_KEYSTORE_GPG, in, flags) == RNP_SUCCESS
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

void tst_RnpPlugin::importUseRemove_data()
{
    QTest::addColumn<bool>("ed25519");
    QTest::addColumn<int>("algorithm");

    QTest::newRow("RSA") << false << int(Crypto::CryptoManager::AlgorithmRsa);
    QTest::newRow("Ed25519") << true << int(Crypto::CryptoManager::AlgorithmEdDsa);
}

// The daemon learns the collection of an imported key, named by its
// key ID, only when it initialises the plugin at start: before that,
// signing, verification, encryption and decryption by reference and
// the removal of the collection fail. They are done after a restart.
void tst_RnpPlugin::importUseRemove()
{
    QFETCH(bool, ed25519);
    QFETCH(int, algorithm);

    QString id;
    QStringList fingerprints;
    const QByteArray data = exportedKey(ed25519, &id, &fingerprints);
    QVERIFY(!data.isEmpty());
    QVERIFY(!id.isEmpty());
    QCOMPARE(fingerprints.size(), 2);
    const QByteArray plaintext("Test plaintext data");

    {
        Crypto::CryptoManager cm;
        // The daemon records the import under the name of the template.
        const QString name = QString::fromLatin1(QTest::currentDataTag());
        Crypto::Key keyTemplate;
        keyTemplate.setIdentifier(Crypto::Key::Identifier(name, QStringLiteral("import"),
                                                          RNP_PLUGIN));
        Crypto::ImportStoredKeyRequest isr;
        isr.setManager(&cm);
        isr.setData(data);
        isr.setKeyTemplate(keyTemplate);
        isr.setCryptoPluginName(RNP_PLUGIN);
        isr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(isr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(isr.result().code(), Crypto::Result::Succeeded);
        const Crypto::Key imported = isr.importedKeyReference();
        QCOMPARE(imported.name(), fingerprints.at(0));
        QCOMPARE(imported.collectionName(), id);
        const QStringList pub = savedFingerprints(QStringLiteral("pubring.gpg"),
                                                  RNP_LOAD_SAVE_PUBLIC_KEYS);
        const QStringList sec = savedFingerprints(QStringLiteral("secring.gpg"),
                                                  RNP_LOAD_SAVE_SECRET_KEYS);
        for (const QString &fp : fingerprints) {
            QVERIFY(pub.contains(fp));
            QVERIFY(sec.contains(fp));
        }

        Crypto::StoredKeyRequest skr;
        skr.setManager(&cm);
        skr.setIdentifier(Crypto::Key::Identifier(fingerprints.at(0), id, RNP_PLUGIN));
        skr.setKeyComponents(Crypto::Key::MetaData | Crypto::Key::PublicKeyData);
        skr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(skr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(skr.result().code(), Crypto::Result::Succeeded);
        QCOMPARE((int)skr.storedKey().algorithm(), algorithm);

        Crypto::SignRequest sr;
        sr.setManager(&cm);
        sr.setKey(imported);
        sr.setData(plaintext);
        sr.setCryptoPluginName(RNP_PLUGIN);
        sr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(sr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(sr.result().code(), Crypto::Result::Succeeded);
        QVERIFY(!sr.signature().isEmpty());
    }

    QVERIFY(stopDaemon());
    QVERIFY(startDaemon());

    {
        Crypto::CryptoManager cm;
        Crypto::StoredKeyIdentifiersRequest skir;
        skir.setManager(&cm);
        skir.setStoragePluginName(RNP_PLUGIN);
        skir.setCollectionName(id);
        skir.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(skir.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(skir.result().code(), Crypto::Result::Succeeded);
        QStringList listed;
        for (const Crypto::Key::Identifier &identifier : skir.identifiers())
            listed << identifier.name();
        listed.sort();
        QStringList expected = fingerprints;
        expected.sort();
        QCOMPARE(listed, expected);

        const Crypto::Key primary(fingerprints.at(0), id, RNP_PLUGIN);
        Crypto::SignRequest sr;
        sr.setManager(&cm);
        sr.setKey(primary);
        sr.setData(plaintext);
        sr.setCryptoPluginName(RNP_PLUGIN);
        sr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(sr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(sr.result().code(), Crypto::Result::Succeeded);

        Crypto::VerifyRequest vr;
        vr.setManager(&cm);
        vr.setKey(primary);
        vr.setData(plaintext);
        vr.setSignature(sr.signature());
        vr.setCryptoPluginName(RNP_PLUGIN);
        vr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(vr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(vr.result().code(), Crypto::Result::Succeeded);
        QCOMPARE(vr.verificationStatus(), Crypto::CryptoManager::VerificationSucceeded);

        const Crypto::Key subkey(fingerprints.at(1), id, RNP_PLUGIN);
        Crypto::EncryptRequest er;
        er.setManager(&cm);
        er.setKey(subkey);
        er.setData(plaintext);
        er.setCryptoPluginName(RNP_PLUGIN);
        er.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(er.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(er.result().code(), Crypto::Result::Succeeded);

        Crypto::DecryptRequest dr;
        dr.setManager(&cm);
        dr.setKey(subkey);
        dr.setData(er.ciphertext());
        dr.setCryptoPluginName(RNP_PLUGIN);
        dr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(dr.status(), Crypto::Request::Finished, TIMEOUT);
        QCOMPARE(dr.result().code(), Crypto::Result::Succeeded);
        QCOMPARE(dr.plaintext(), plaintext);

        Secrets::SecretManager sm;
        Secrets::DeleteCollectionRequest dcr;
        dcr.setManager(&sm);
        dcr.setCollectionName(id);
        dcr.setStoragePluginName(RNP_PLUGIN);
        dcr.setUserInteractionMode(Secrets::SecretManager::PreventInteraction);
        dcr.startRequest();
        QTRY_COMPARE_WITH_TIMEOUT(dcr.status(), Secrets::Request::Finished, TIMEOUT);
        QCOMPARE(dcr.result().code(), Secrets::Result::Succeeded);
        const QStringList pub = savedFingerprints(QStringLiteral("pubring.gpg"),
                                                  RNP_LOAD_SAVE_PUBLIC_KEYS);
        const QStringList sec = savedFingerprints(QStringLiteral("secring.gpg"),
                                                  RNP_LOAD_SAVE_SECRET_KEYS);
        for (const QString &fp : fingerprints) {
            QVERIFY(!pub.contains(fp));
            QVERIFY(!sec.contains(fp));
        }
    }
}

QTEST_GUILESS_MAIN(tst_RnpPlugin)
#include "tst_rnpplugin.moc"
