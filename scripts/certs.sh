#!/usr/bin/env bash
set -euo pipefail
cd /usr/share/elasticsearch
spec_hash=$(sha256sum /instances.yml | cut -d ' ' -f 1)
if [[ -s /certs/elasticsearch/elasticsearch.crt && -s /certs/instances.sha256 && "$(cat /certs/instances.sha256)" != "$spec_hash" ]]; then
  echo 'TLS names changed. Use the documented certificate rotation procedure before restarting.' >&2
  exit 1
fi
if [[ ! -s /certs/ca/ca.crt ]]; then
  bin/elasticsearch-certutil ca --silent --pem --out /certs/ca.zip
  unzip -oq /certs/ca.zip -d /certs
  rm /certs/ca.zip
fi
if [[ ! -s /certs/elasticsearch/elasticsearch.crt ]]; then
  bin/elasticsearch-certutil cert --silent --pem --in /instances.yml \
    --ca-cert /certs/ca/ca.crt --ca-key /certs/ca/ca.key --out /certs/instances.zip
  unzip -oq /certs/instances.zip -d /certs
  rm /certs/instances.zip
  printf '%s\n' "$spec_hash" > /certs/instances.sha256
fi
chown -R root:0 /certs
find /certs -type d -exec chmod 750 {} \;
find /certs -type f -exec chmod 640 {} \;
