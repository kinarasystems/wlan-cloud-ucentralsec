#!/bin/sh
set -e

if [ "$SELFSIGNED_CERTS" = 'true' ]; then
    update-ca-certificates
fi

if [[ "$TEMPLATE_CONFIG" = 'true' && ! -f "$OWSEC_CONFIG"/owsec.properties ]]; then
  RESTAPI_HOST_ROOTCA=${RESTAPI_HOST_ROOTCA:-"\$OWSEC_ROOT/certs/restapi-ca.pem"} \
  RESTAPI_HOST_PORT=${RESTAPI_HOST_PORT:-"16001"} \
  RESTAPI_HOST_CERT=${RESTAPI_HOST_CERT:-"\$OWSEC_ROOT/certs/restapi-cert.pem"} \
  RESTAPI_HOST_KEY=${RESTAPI_HOST_KEY:-"\$OWSEC_ROOT/certs/restapi-key.pem"} \
  RESTAPI_HOST_KEY_PASSWORD=${RESTAPI_HOST_KEY_PASSWORD:-"mypassword"} \
  RESTAPI_WWWASSETS=${RESTAPI_WWWASSETS:-"\$OWSEC_ROOT/wwwassets"} \
  INTERNAL_RESTAPI_HOST_ROOTCA=${INTERNAL_RESTAPI_HOST_ROOTCA:-"\$OWSEC_ROOT/certs/restapi-ca.pem"} \
  INTERNAL_RESTAPI_HOST_PORT=${INTERNAL_RESTAPI_HOST_PORT:-"17001"} \
  INTERNAL_RESTAPI_HOST_CERT=${INTERNAL_RESTAPI_HOST_CERT:-"\$OWSEC_ROOT/certs/restapi-cert.pem"} \
  INTERNAL_RESTAPI_HOST_KEY=${INTERNAL_RESTAPI_HOST_KEY:-"\$OWSEC_ROOT/certs/restapi-key.pem"} \
  INTERNAL_RESTAPI_HOST_KEY_PASSWORD=${INTERNAL_RESTAPI_HOST_KEY_PASSWORD:-"mypassword"} \
  AUTHENTICATION_DEFAULT_USERNAME=${AUTHENTICATION_DEFAULT_USERNAME:-"tip@ucentral.com"} \
  AUTHENTICATION_DEFAULT_PASSWORD=${AUTHENTICATION_DEFAULT_PASSWORD:-"13268b7daa751240369d125e79c873bd8dd3bef7981bdfd38ea03dbb1fbe7dcf"} \
  SYSTEM_DATA=${SYSTEM_DATA:-"\$OWSEC_ROOT/data"} \
  SYSTEM_URI_PRIVATE=${SYSTEM_URI_PRIVATE:-"https://localhost:17001"} \
  SYSTEM_URI_PUBLIC=${SYSTEM_URI_PUBLIC:-"https://localhost:16001"} \
  SYSTEM_URI_UI=${SYSTEM_URI_UI:-"http://localhost"} \
  SERVICE_KEY=${SERVICE_KEY:-"\$OWSEC_ROOT/certs/restapi-key.pem"} \
  SERVICE_KEY_PASSWORD=${SERVICE_KEY_PASSWORD:-"mypassword"} \
  MAILER_HOSTNAME=${MAILER_HOSTNAME:-"smtp.gmail.com"} \
  MAILER_USERNAME=${MAILER_USERNAME:-"************************"} \
  MAILER_PASSWORD=${MAILER_PASSWORD:-"************************"} \
  MAILER_SENDER=${MAILER_SENDER:-"OpenWIFI"} \
  MAILER_PORT=${MAILER_PORT:-"587"} \
  KAFKA_ENABLE=${KAFKA_ENABLE:-"true"} \
  KAFKA_BROKERLIST=${KAFKA_BROKERLIST:-"localhost:9092"} \
  STORAGE_TYPE=${STORAGE_TYPE:-"sqlite"} \
  STORAGE_TYPE_POSTGRESQL_HOST=${STORAGE_TYPE_POSTGRESQL_HOST:-"localhost"} \
  STORAGE_TYPE_POSTGRESQL_USERNAME=${STORAGE_TYPE_POSTGRESQL_USERNAME:-"owsec"} \
  STORAGE_TYPE_POSTGRESQL_PASSWORD=${STORAGE_TYPE_POSTGRESQL_PASSWORD:-"owsec"} \
  STORAGE_TYPE_POSTGRESQL_DATABASE=${STORAGE_TYPE_POSTGRESQL_DATABASE:-"owsec"} \
  STORAGE_TYPE_POSTGRESQL_PORT=${STORAGE_TYPE_POSTGRESQL_PORT:-"5432"} \
  STORAGE_TYPE_MYSQL_HOST=${STORAGE_TYPE_MYSQL_HOST:-"localhost"} \
  STORAGE_TYPE_MYSQL_USERNAME=${STORAGE_TYPE_MYSQL_USERNAME:-"owsec"} \
  STORAGE_TYPE_MYSQL_PASSWORD=${STORAGE_TYPE_MYSQL_PASSWORD:-"owsec"} \
  STORAGE_TYPE_MYSQL_DATABASE=${STORAGE_TYPE_MYSQL_DATABASE:-"owsec"} \
  STORAGE_TYPE_MYSQL_PORT=${STORAGE_TYPE_MYSQL_PORT:-"3306"} \
  envsubst < $OWSEC_CONFIG/owsec.properties.tmpl > $OWSEC_CONFIG/owsec.properties
fi

if [ "$1" = '/openwifi/owsec' -a "$(id -u)" = '0' ]; then
    if [ "$RUN_CHOWN" = 'true' ]; then
      chown -R "$OWSEC_USER": "$OWSEC_ROOT" "$OWSEC_CONFIG"
    fi
    exec su-exec "$OWSEC_USER" "$@"
fi

exec "$@"
