#ifndef SSHVPNPROTOCOL_H
#define SSHVPNPROTOCOL_H

#include <QByteArray>
#include <QProcess>
#include <QTemporaryFile>

#include "core/ipcclient.h"
#include "settings.h"
#include "vpnprotocol.h"

#include <QtCore/qsharedpointer.h>

class SshVpnProtocol : public VpnProtocol
{
    Q_OBJECT
public:
    explicit SshVpnProtocol(const QJsonObject &configuration, QObject *parent = nullptr);
    ~SshVpnProtocol() override;

    ErrorCode start() override;
    void stop() override;

private:
    ErrorCode setupRouting();
    ErrorCode startTun2Socks();
    static quint16 pickLocalSocksPort();
    void removeSshAskpassScript();

    QJsonObject m_sshConfig;
    Settings::RouteMode m_routeMode {};
    QList<QHostAddress> m_dnsServers;
    QString m_remoteAddress;

    QString m_sshHost;
    QString m_sshUser;
    QString m_sshPassword;
    QString m_sshPort;

    quint16 m_localSocksPort = 0;

    QTemporaryFile m_passwordFile;
    QString m_sshAskpassScriptPath;

    QProcess m_sshProcess;
    QByteArray m_sshOutputCapture;
    QSharedPointer<IpcProcessInterfaceReplica> m_tun2socksProcess;
};

#endif
