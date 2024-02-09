sudo docker run -d \
--restart always \
--log-driver none \
-p $SSH_TUNNEL_PORT:22/tcp \
--name $CONTAINER_NAME \
$CONTAINER_NAME
