#include "sshvpnprotocol.h"

#include "core/ipcclient.h"
#include "core/networkUtilities.h"
#include "ipc.h"
#include "protocols/protocols_defs.h"
#include "utilities.h"

#include <QCoreApplication>
#include <QDir>
#include <QAbstractSocket>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QProcessEnvironment>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QUuid>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QtGlobal>

#ifdef Q_OS_MACOS
static const QString tunName = "utun22";
#else
static const QString tunName = "tun2";
#endif

namespace {

QString findExe(const QString &name)
{
    const QString p = QStandardPaths::findExecutable(name);
    if (!p.isEmpty())
        return p;
#ifdef Q_OS_WIN
    static const QStringList dirs { QStringLiteral("C:/Windows/System32/OpenSSH"),
                                    QStringLiteral("C:/Program Files/Git/usr/bin") };
    for (const QString &dir : dirs) {
        const QString cand = dir + QLatin1Char('/') + name + QStringLiteral(".exe");
        const QFileInfo fi(cand);
        if (fi.exists() && fi.isExecutable())
            return cand;
    }
#else
    static const QStringList dirs { QStringLiteral("/usr/bin"), QStringLiteral("/bin") };
    for (const QString &dir : dirs) {
        const QString cand = dir + QLatin1Char('/') + name;
        const QFileInfo fi(cand);
        if (fi.exists() && fi.isExecutable())
            return cand;
    }
#endif
    return {};
}

} // namespace

SshVpnProtocol::SshVpnProtocol(const QJsonObject &configuration, QObject *parent)
    : VpnProtocol(configuration, parent)
{
    m_vpnGateway = amnezia::protocols::sshTunnel::defaultLocalAddr;
    m_vpnLocalAddress = amnezia::protocols::sshTunnel::defaultLocalAddr;
    m_routeGateway = NetworkUtilities::getGatewayAndIface().first;

    m_routeMode = static_cast<Settings::RouteMode>(configuration.value(amnezia::config_key::splitTunnelType).toInt());
    m_remoteAddress = NetworkUtilities::getIPAddress(m_rawConfig.value(amnezia::config_key::hostName).toString());
    m_sshHost = m_rawConfig.value(amnezia::config_key::hostName).toString();

    const QString primaryDns = configuration.value(amnezia::config_key::dns1).toString();
    m_dnsServers.push_back(QHostAddress(primaryDns));
    if (primaryDns != amnezia::protocols::dns::amneziaDnsIp) {
        const QString secondaryDns = configuration.value(amnezia::config_key::dns2).toString();
        m_dnsServers.push_back(QHostAddress(secondaryDns));
    }

    m_sshConfig = configuration.value(ProtocolProps::key_proto_config_data(Proto::SshTunnel)).toObject();
}

SshVpnProtocol::~SshVpnProtocol()
{
    SshVpnProtocol::stop();
}

quint16 SshVpnProtocol::pickLocalSocksPort()
{
    for (int i = 0; i < 100; ++i) {
        quint32 p = QRandomGenerator::global()->generate();
        p = static_cast<quint32>((65000.0 - 18001.0) * p / UINT32_MAX + 18001);

        QTcpServer s;
        if (s.listen(QHostAddress::LocalHost, static_cast<quint16>(p)))
            return static_cast<quint16>(p);
    }
    return 18990;
}

static void appendSshCapture(QByteArray *capture, const QByteArray &chunk)
{
    if (!capture || chunk.isEmpty())
        return;
    constexpr qsizetype kMaxCapture = 16384;
    capture->append(chunk);
    if (capture->size() > kMaxCapture)
        *capture = capture->right(kMaxCapture);
}

// QProcess delivers stdout/stderr via the event loop; a tight msleep loop never processes it.
static bool waitForLocalPort(quint16 port, int timeoutMs, QProcess *drainProcess, QByteArray *captureOut)
{
    const int step = 100;
    int waited = 0;
    while (waited < timeoutMs) {
        if (drainProcess) {
            if (QCoreApplication::instance())
                QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
            drainProcess->waitForReadyRead(0);
            const QByteArray chunk = drainProcess->readAllStandardOutput();
            if (!chunk.isEmpty()) {
                qDebug().noquote() << "[ssh]" << chunk;
                appendSshCapture(captureOut, chunk);
            }
        }

        QTcpSocket probe;
        probe.connectToHost(QHostAddress::LocalHost, port);
        if (probe.waitForConnected(step)) {
            probe.disconnectFromHost();
            return true;
        }
        QThread::msleep(step);
        waited += step;
    }
    return false;
}

void SshVpnProtocol::removeSshAskpassScript()
{
    if (m_sshAskpassScriptPath.isEmpty())
        return;
    QFile::remove(m_sshAskpassScriptPath);
    m_sshAskpassScriptPath.clear();
}

ErrorCode SshVpnProtocol::start()
{
    const QString sshBin = findExe(QStringLiteral("ssh"));
    if (sshBin.isEmpty()) {
        setLastError(ErrorCode::ExecutableMissing);
        return lastError();
    }

    m_sshUser = m_sshConfig.value(config_key::userName).toString(protocols::sshTunnel::defaultUserName);
    m_sshPassword = m_sshConfig.value(config_key::password).toString();
    m_sshPort = m_sshConfig.value(config_key::port).toString(protocols::sshTunnel::defaultPort);

    if (m_sshHost.isEmpty() || m_sshUser.isEmpty() || m_sshPassword.isEmpty()) {
        setLastError(ErrorCode::InternalError);
        return lastError();
    }

#ifdef AMNEZIA_DESKTOP
    const ErrorCode res = IpcClient::withInterface([&](QSharedPointer<IpcInterfaceReplica> iface) {
        QString ip = NetworkUtilities::getIPAddress(m_rawConfig.value(amnezia::config_key::hostName).toString());
        QRemoteObjectPendingReply<bool> reply = iface->addKillSwitchAllowedRange(QStringList(ip));
        if (!reply.waitForFinished(1000) || !reply.returnValue()) {
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        return ErrorCode::NoError;
    });
    if (res != ErrorCode::NoError) {
        return res;
    }
#endif

    m_passwordFile.setAutoRemove(true);
    if (!m_passwordFile.open()) {
        setLastError(ErrorCode::InternalError);
        return lastError();
    }
    m_passwordFile.write(m_sshPassword.toUtf8());
    m_passwordFile.close();

    // Do not use QTemporaryFile for the askpass script: Linux returns ETXTBUSY if exec runs while the
    // creating process still has the inode open for writing (common with QFile/QTemporaryFile lifecycle).
    removeSshAskpassScript();
#ifdef Q_OS_WIN
    m_sshAskpassScriptPath = QDir::tempPath() + QLatin1Char('/') + QStringLiteral("amnezia-ssh-askpass-")
            + QUuid::createUuid().toString(QUuid::WithoutBraces) + QStringLiteral(".cmd");
    {
        QString pwPath = QDir::toNativeSeparators(m_passwordFile.fileName());
        pwPath.replace(QLatin1Char('"'), QLatin1String("\"\""));
        const QByteArray script = QByteArrayLiteral("@echo off\r\ntype \"") + pwPath.toUtf8() + QByteArrayLiteral("\"\r\n");
        QFile askF(m_sshAskpassScriptPath);
        if (!askF.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
            removeSshAskpassScript();
            setLastError(ErrorCode::InternalError);
            return lastError();
        }
        askF.write(script);
        if (!askF.flush()) {
            askF.close();
            removeSshAskpassScript();
            setLastError(ErrorCode::InternalError);
            return lastError();
        }
        askF.close();
    }
#else
    m_sshAskpassScriptPath = QDir::tempPath() + QLatin1Char('/') + QStringLiteral("amnezia-ssh-askpass-")
            + QUuid::createUuid().toString(QUuid::WithoutBraces) + QStringLiteral(".sh");
    QString pwPath = m_passwordFile.fileName();
    pwPath.replace(QLatin1Char('\''), QLatin1String("'\\''"));
    const QByteArray script = "#!/bin/sh\nexec cat '" + pwPath.toUtf8() + "'\n";
    QFile askF(m_sshAskpassScriptPath);
    if (!askF.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        removeSshAskpassScript();
        setLastError(ErrorCode::InternalError);
        return lastError();
    }
    askF.write(script);
    if (!askF.flush()) {
        askF.close();
        removeSshAskpassScript();
        setLastError(ErrorCode::InternalError);
        return lastError();
    }
    askF.close();
    if (!QFile::setPermissions(m_sshAskpassScriptPath,
                               QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner)) {
        removeSshAskpassScript();
        setLastError(ErrorCode::InternalError);
        return lastError();
    }
#endif

    m_localSocksPort = pickLocalSocksPort();
    m_sshOutputCapture.clear();

    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
#ifndef Q_OS_WIN
    // Never force DISPLAY=:0 — it breaks SSH_ASKPASS on Wayland / XWayland (often :1 or unset).
    if (env.value(QStringLiteral("DISPLAY")).isEmpty())
        env.insert(QStringLiteral("DISPLAY"), QStringLiteral(":0"));
#endif
    env.insert(QStringLiteral("SSH_ASKPASS"), m_sshAskpassScriptPath);
    env.insert(QStringLiteral("SSH_ASKPASS_REQUIRE"), QStringLiteral("force"));
    // Avoid user-wide ssh_config surprises (ProxyCommand, huge ConnectTimeout, etc.).
    static const char *kProxyEnv[] = { "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY",
                                       "https_proxy", "NO_PROXY", "no_proxy", "FTP_PROXY", "ftp_proxy" };
    for (const char *k : kProxyEnv)
        env.remove(QLatin1String(k));

    // Ignore ~/.ssh/config (ProxyCommand, etc.). Verbose SSH: AMNEZIA_SSH_VERBOSE=1 (adds -v; Linux uses stdbuf).
    const bool sshVerbose = !qgetenv("AMNEZIA_SSH_VERBOSE").isEmpty();
#ifdef Q_OS_WIN
    const QString sshNullConfig = QStringLiteral("NUL");
#else
    const QString sshNullConfig = QStringLiteral("/dev/null");
#endif
    QStringList sshArgs;
    sshArgs << QStringLiteral("-F") << sshNullConfig;
    if (sshVerbose)
        sshArgs << QStringLiteral("-v");
    sshArgs << QStringLiteral("-n")
            << QStringLiteral("-N")
            << QStringLiteral("-D")
            << (QStringLiteral("127.0.0.1:") + QString::number(m_localSocksPort))
            << QStringLiteral("-p") << m_sshPort << QStringLiteral("-o") << QStringLiteral("StrictHostKeyChecking=no")
#ifdef Q_OS_WIN
            << QStringLiteral("-o") << QStringLiteral("UserKnownHostsFile=NUL") << QStringLiteral("-o")
#else
            << QStringLiteral("-o") << QStringLiteral("UserKnownHostsFile=/dev/null") << QStringLiteral("-o")
#endif
            << QStringLiteral("Compression=no") << QStringLiteral("-o") << QStringLiteral("TCPKeepAlive=yes")
            << QStringLiteral("-o") << QStringLiteral("ServerAliveInterval=30") << QStringLiteral("-o")
            << QStringLiteral("IPQoS=throughput") << QStringLiteral("-o") << QStringLiteral("BatchMode=no")
            << QStringLiteral("-o") << QStringLiteral("ConnectTimeout=18") << QStringLiteral("-o")
            << QStringLiteral("ExitOnForwardFailure=yes") << QStringLiteral("-o")
            << QStringLiteral("GSSAPIAuthentication=no") << QStringLiteral("-o")
            << QStringLiteral("Ciphers=aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com")
            << QStringLiteral("-o") << QStringLiteral("MACs=hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com")
            << QStringLiteral("-o") << QStringLiteral("KexAlgorithms=curve25519-sha256,ecdh-sha2-nistp256")
            << (m_sshUser + QLatin1Char('@') + m_sshHost);

    QString sshProgram = sshBin;
    QStringList args = sshArgs;
#ifdef Q_OS_LINUX
    const QString stdbufBin = findExe(QStringLiteral("stdbuf"));
    const QString setsidBin = findExe(QStringLiteral("setsid"));
    const bool useStdbuf = sshVerbose && !stdbufBin.isEmpty();
    if (!setsidBin.isEmpty()) {
        sshProgram = setsidBin;
        if (useStdbuf)
            args = QStringList{ stdbufBin, QStringLiteral("-o0"), QStringLiteral("-e0"), QStringLiteral("--"),
                                sshBin } + sshArgs;
        else
            args = QStringList{ sshBin } + sshArgs;
    } else if (useStdbuf) {
        sshProgram = stdbufBin;
        args = QStringList{ QStringLiteral("-o0"), QStringLiteral("-e0"), QStringLiteral("--"), sshBin } + sshArgs;
    }
#endif

    m_sshProcess.setProcessEnvironment(env);
    m_sshProcess.setProcessChannelMode(QProcess::MergedChannels);

    connect(&m_sshProcess, &QProcess::readyReadStandardOutput, this, [this]() {
        const QByteArray out = m_sshProcess.readAllStandardOutput();
        if (!out.isEmpty()) {
            qDebug().noquote() << "[ssh]" << out;
            appendSshCapture(&m_sshOutputCapture, out);
        }
    });

    connect(&m_sshProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus exitStatus) {
                qDebug().noquote() << "SshVpnProtocol: ssh finished" << exitCode << exitStatus;
                if (m_connectionState == Vpn::ConnectionState::Connected || m_connectionState == Vpn::ConnectionState::Connecting) {
                    emit protocolError(ErrorCode::InternalError);
                }
                stop();
            });

    qDebug().noquote() << "SshVpnProtocol::start" << sshProgram << args.join(QLatin1Char(' '));

    setConnectionState(Vpn::ConnectionState::Connecting);
    m_sshProcess.start(sshProgram, args);
    if (!m_sshProcess.waitForStarted(8000)) {
        stop();
        setLastError(ErrorCode::ExecutableMissing);
        return lastError();
    }

    // Must exceed ConnectTimeout + auth/forward setup (ConnectTimeout alone can burn ~18s with no SOCKS yet).
    if (!waitForLocalPort(m_localSocksPort, 45000, &m_sshProcess, &m_sshOutputCapture)) {
        qCritical().noquote() << "SshVpnProtocol: SOCKS port did not open in time; ssh state" << m_sshProcess.state()
#ifndef Q_OS_WIN
                              << "DISPLAY" << env.value(QStringLiteral("DISPLAY"))
#endif
                              << "cmd" << sshProgram
                              << args.join(QLatin1Char(' '));
        if (!m_sshOutputCapture.isEmpty())
            qCritical().noquote() << "SshVpnProtocol: ssh log:" << m_sshOutputCapture;
        else
            qCritical() << "SshVpnProtocol: no ssh stdout/stderr yet (often hung auth or blocked forwarding)";
        stop();
        setLastError(ErrorCode::InternalError);
        return lastError();
    }

    return startTun2Socks();
}

void SshVpnProtocol::stop()
{
    qDebug() << "SshVpnProtocol::stop()";

    QObject::disconnect(&m_sshProcess, nullptr, this, nullptr);

    // tun2socks must release the TUN before deleteTun; otherwise deleteTun fails (and teardown is inconsistent).
    if (m_tun2socksProcess) {
        m_tun2socksProcess->blockSignals(true);
        m_tun2socksProcess->terminate();
        auto waitForFinished = m_tun2socksProcess->waitForFinished(3000);
        if (!waitForFinished.waitForFinished() || !waitForFinished.returnValue()) {
            m_tun2socksProcess->kill();
            auto waitKill = m_tun2socksProcess->waitForFinished(2000);
            waitKill.waitForFinished();
        }
        m_tun2socksProcess->close();
        m_tun2socksProcess.reset();
    }

    IpcClient::withInterface([](QSharedPointer<IpcInterfaceReplica> iface) {
        auto disableKillSwitch = iface->disableKillSwitch();
        if (!disableKillSwitch.waitForFinished() || !disableKillSwitch.returnValue())
            qWarning() << "SshVpnProtocol::stop: Failed to disable killswitch";

        auto StartRoutingIpv6 = iface->StartRoutingIpv6();
        if (!StartRoutingIpv6.waitForFinished() || !StartRoutingIpv6.returnValue())
            qWarning() << "SshVpnProtocol::stop: Failed to start routing ipv6";

        auto restoreResolvers = iface->restoreResolvers();
        if (!restoreResolvers.waitForFinished() || !restoreResolvers.returnValue())
            qWarning() << "SshVpnProtocol::stop: Failed to restore resolvers";

        auto deleteTun = iface->deleteTun(tunName);
        if (!deleteTun.waitForFinished() || !deleteTun.returnValue())
            qWarning() << "SshVpnProtocol::stop: Failed to delete tun";
    });

    if (m_sshProcess.state() != QProcess::NotRunning) {
        m_sshProcess.terminate();
        if (!m_sshProcess.waitForFinished(2000)) {
            m_sshProcess.kill();
            m_sshProcess.waitForFinished(1000);
        }
    }

    removeSshAskpassScript();

    setConnectionState(Vpn::ConnectionState::Disconnected);
}

ErrorCode SshVpnProtocol::startTun2Socks()
{
    m_tun2socksProcess = IpcClient::CreatePrivilegedProcess();
    if (!m_tun2socksProcess->waitForSource()) {
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

    const QString proxyUrl = QStringLiteral("socks5://127.0.0.1:") + QString::number(m_localSocksPort);

    m_tun2socksProcess->setProgram(PermittedProcess::Tun2Socks);
    m_tun2socksProcess->setArguments({ "-device", QStringLiteral("tun://%1").arg(tunName), "-proxy", proxyUrl });

    connect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardOutput, this, [this]() {
        auto readAllStandardOutput = m_tun2socksProcess->readAllStandardOutput();
        if (!readAllStandardOutput.waitForFinished()) {
            qWarning() << "SshVpnProtocol: Failed to read output from tun2socks";
            return;
        }

        const QString line = readAllStandardOutput.returnValue();

        if (!line.contains("[TCP]") && !line.contains("[UDP]"))
            qDebug().noquote() << "[tun2socks]" << line;

        if (line.contains("[STACK] tun://") && line.contains(QLatin1String("<-> socks5://"))) {
            disconnect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::readyReadStandardOutput, this, nullptr);

            if (ErrorCode res = setupRouting(); res != ErrorCode::NoError) {
                stop();
                setLastError(res);
            } else {
                setConnectionState(Vpn::ConnectionState::Connected);
            }
        }
    }, Qt::QueuedConnection);

    connect(m_tun2socksProcess.data(), &IpcProcessInterfaceReplica::finished, this, [this](int exitCode, QProcess::ExitStatus exitStatus) {
        if (exitStatus == QProcess::ExitStatus::CrashExit) {
            qCritical() << "SshVpnProtocol: tun2socks crashed";
        } else {
            qCritical() << "SshVpnProtocol: tun2socks exited" << exitCode;
        }
        stop();
        setLastError(ErrorCode::Tun2SockExecutableCrashed);
    }, Qt::QueuedConnection);

    m_tun2socksProcess->start();
    return ErrorCode::NoError;
}

ErrorCode SshVpnProtocol::setupRouting()
{
    return IpcClient::withInterface(
            [this](QSharedPointer<IpcInterfaceReplica> iface) -> ErrorCode {
#ifdef Q_OS_WIN
                const int inetAdapterIndex = NetworkUtilities::AdapterIndexTo(QHostAddress(m_remoteAddress));
#endif
                auto createTun = iface->createTun(tunName, amnezia::protocols::sshTunnel::defaultLocalAddr);
                if (!createTun.waitForFinished() || !createTun.returnValue()) {
                    qCritical() << "SshVpnProtocol: Failed to assign IP address for TUN";
                    return ErrorCode::InternalError;
                }

                auto updateResolvers = iface->updateResolvers(tunName, m_dnsServers);
                if (!updateResolvers.waitForFinished() || !updateResolvers.returnValue()) {
                    qCritical() << "SshVpnProtocol: Failed to set DNS resolvers for TUN";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                int vpnAdapterIndex = -1;
                QList<QNetworkInterface> netInterfaces = QNetworkInterface::allInterfaces();
                for (auto &netInterface : netInterfaces) {
                    for (auto &address : netInterface.addressEntries()) {
                        if (m_vpnLocalAddress == address.ip().toString())
                            vpnAdapterIndex = netInterface.index();
                    }
                }
#else
                static const int vpnAdapterIndex = 0;
#endif
                const bool killSwitchEnabled = QVariant(m_rawConfig.value(config_key::killSwitchOption).toString()).toBool();
                if (killSwitchEnabled) {
                    if (vpnAdapterIndex != -1) {
                        QJsonObject config = m_rawConfig;
                        config.insert("vpnServer", m_remoteAddress);

                        auto enableKillSwitch = IpcClient::Interface()->enableKillSwitch(config, vpnAdapterIndex);
                        if (!enableKillSwitch.waitForFinished() || !enableKillSwitch.returnValue()) {
                            qCritical() << "SshVpnProtocol: Failed to enable killswitch";
                            return ErrorCode::InternalError;
                        }
                    } else
                        qWarning() << "SshVpnProtocol: killswitch disabled (no adapter index)";
                }

                if (m_routeMode == Settings::RouteMode::VpnAllSites) {
                    // Linux: default routes via TUN would steal packets to the SSH server itself (150.x is in 128.0.0.0/1).
                    // Windows uses enablePeerTraffic for this; add a host route via the physical gateway first.
#ifdef Q_OS_LINUX
                    if (NetworkUtilities::checkIPv4Format(m_remoteAddress)
                        && NetworkUtilities::checkIPv4Format(m_routeGateway)) {
                        const QString hostBypass = m_remoteAddress + QStringLiteral("/32");
                        auto bypassReply = iface->routeAddList(m_routeGateway, QStringList{ hostBypass });
                        if (!bypassReply.waitForFinished() || bypassReply.returnValue() != 1)
                            qWarning() << "SshVpnProtocol: failed to add SSH host bypass route" << hostBypass << "via"
                                       << m_routeGateway;
                    }
#endif
                    static const QStringList subnets = { "1.0.0.0/8",   "2.0.0.0/7",   "4.0.0.0/6",  "8.0.0.0/5",
                                                           "16.0.0.0/4",  "32.0.0.0/3",  "64.0.0.0/2", "128.0.0.0/1" };

                    auto routeAddList = iface->routeAddList(m_vpnGateway, subnets);
                    if (!routeAddList.waitForFinished() || routeAddList.returnValue() != subnets.count()) {
                        qCritical() << "SshVpnProtocol: Failed to set routes for TUN";
                        return ErrorCode::InternalError;
                    }
                }

                auto StopRoutingIpv6 = iface->StopRoutingIpv6();
                if (!StopRoutingIpv6.waitForFinished() || !StopRoutingIpv6.returnValue()) {
                    qCritical() << "SshVpnProtocol: Failed to disable IPv6 routing";
                    return ErrorCode::InternalError;
                }

#ifdef Q_OS_WIN
                if (inetAdapterIndex != -1 && vpnAdapterIndex != -1) {
                    QJsonObject config = m_rawConfig;
                    config.insert("inetAdapterIndex", inetAdapterIndex);
                    config.insert("vpnAdapterIndex", vpnAdapterIndex);
                    config.insert("vpnGateway", m_vpnGateway);
                    config.insert("vpnServer", m_remoteAddress);

                    auto enablePeerTraffic = iface->enablePeerTraffic(config);
                    if (!enablePeerTraffic.waitForFinished() || !enablePeerTraffic.returnValue()) {
                        qCritical() << "SshVpnProtocol: Failed to enable peer traffic";
                        return ErrorCode::InternalError;
                    }
                } else
                    qWarning() << "SshVpnProtocol: split-tunneling disabled (adapter indexes)";
#endif
                return ErrorCode::NoError;
            },
            []() { return ErrorCode::AmneziaServiceConnectionFailed; });
}
