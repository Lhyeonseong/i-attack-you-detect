#!/bin/sh
set -eu

mkdir -p /opt/target/uploads /var/log/target
touch /var/log/target/application.log

exec java -jar /app/app.jar
