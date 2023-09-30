#ifndef SSH_TUNNEL_CONFIGURATOR_H
#define SSH_TUNNEL_CONFIGURATOR_H

#include "configurator_base.h"

class SshTunnelConfigurator : public ConfiguratorBase
{
    Q_OBJECT
public:
    explicit SshTunnelConfigurator(std::shared_ptr<Settings> settings, const QSharedPointer<ServerController> &serverController,
                                     QObject *parent = nullptr);

    QString createConfig(const ServerCredentials &credentials, DockerContainer container, const QJsonObject &containerConfig,
                         ErrorCode &errorCode) override;
};

#endif
