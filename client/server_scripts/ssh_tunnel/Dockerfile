FROM alpine:3.19

LABEL maintainer="AmneziaVPN"

RUN apk add --no-cache openssh-server \
    && ssh-keygen -A \
    && mkdir -p /var/run/sshd /opt/amnezia \
    && printf '%s\n' '#!/bin/sh' 'exec tail -f /dev/null' > /opt/amnezia/start.sh \
    && chmod a+x /opt/amnezia/start.sh

EXPOSE 22

ENTRYPOINT ["/bin/sh", "/opt/amnezia/start.sh"]
CMD [""]
