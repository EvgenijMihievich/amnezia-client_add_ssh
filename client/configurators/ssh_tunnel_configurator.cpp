#include "ssh_tunnel_configurator.h"

#include <QJsonDocument>
#include <QJsonObject>

#include "containers/containers_defs.h"
#include "core/controllers/serverController.h"

SshTunnelConfigurator::SshTunnelConfigurator(std::shared_ptr<Settings> settings, const QSharedPointer<ServerController> &serverController,
                                             QObject *parent)
    : ConfiguratorBase(settings, serverController, parent)
{
}

QString SshTunnelConfigurator::createConfig(const ServerCredentials &credentials, DockerContainer container,
                                            const QJsonObject &containerConfig, ErrorCode &errorCode)
{
    Q_UNUSED(credentials);
    Q_UNUSED(container);
    Q_UNUSED(errorCode);

    const QJsonObject ssh = containerConfig.value(ProtocolProps::protoToString(Proto::SshTunnel)).toObject();

    QJsonObject j;
    j.insert(config_key::config, QString());
    j.insert(config_key::port, ssh.value(config_key::port).toString(protocols::sshTunnel::defaultPort));
    j.insert(config_key::userName, ssh.value(config_key::userName).toString(protocols::sshTunnel::defaultUserName));
    j.insert(config_key::password, ssh.value(config_key::password).toString());

    return QJsonDocument(j).toJson();
}
