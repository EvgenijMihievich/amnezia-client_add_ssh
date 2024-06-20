#include "sshTunnelConfigModel.h"

#include "protocols/protocols_defs.h"

SshTunnelConfigModel::SshTunnelConfigModel(QObject *parent) : QAbstractListModel(parent)
{
}

int SshTunnelConfigModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return 1;
}

bool SshTunnelConfigModel::setData(const QModelIndex &index, const QVariant &value, int role)
{
    if (!index.isValid() || index.row() != 0) {
        return false;
    }

    switch (role) {
    case Roles::PortRole: m_protocolConfig.insert(config_key::port, value.toString()); break;
    case Roles::UserNameRole: m_protocolConfig.insert(config_key::userName, value.toString()); break;
    case Roles::PasswordRole: m_protocolConfig.insert(config_key::password, value.toString()); break;
    default: return false;
    }

    emit dataChanged(index, index, QList { role });
    return true;
}

QVariant SshTunnelConfigModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() != 0) {
        return QVariant();
    }

    switch (role) {
    case Roles::PortRole:
        return m_protocolConfig.value(config_key::port).toString();
    case Roles::UserNameRole:
        return m_protocolConfig.value(config_key::userName).toString();
    case Roles::PasswordRole:
        return m_protocolConfig.value(config_key::password).toString();
    default: return QVariant();
    }
}

void SshTunnelConfigModel::updateModel(const QJsonObject &config)
{
    beginResetModel();
    m_container = ContainerProps::containerFromString(config.value(config_key::container).toString());

    m_fullConfig = config;
    const QJsonObject protocolConfig = config.value(config_key::sshtunnel).toObject();

    m_protocolConfig.insert(config_key::userName, protocolConfig.value(config_key::userName).toString());
    m_protocolConfig.insert(config_key::password, protocolConfig.value(config_key::password).toString());
    m_protocolConfig.insert(config_key::port, protocolConfig.value(config_key::port).toString());

    endResetModel();
}

QJsonObject SshTunnelConfigModel::getConfig()
{
    m_fullConfig.insert(config_key::sshtunnel, m_protocolConfig);
    return m_fullConfig;
}

QHash<int, QByteArray> SshTunnelConfigModel::roleNames() const
{
    QHash<int, QByteArray> roles;

    roles[PortRole] = "port";
    roles[UserNameRole] = "username";
    roles[PasswordRole] = "password";

    return roles;
}
