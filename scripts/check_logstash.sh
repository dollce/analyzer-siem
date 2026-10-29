#!/usr/bin/env bash
# Compile the real pipeline with no network, input data or SIEM runtime.
set -euo pipefail
cd "$(dirname "$0")/.."
project_dir=$(pwd)
# Optional alternate profile/case registries for isolated checks, never input logs.
profile_config=${1:-"$project_dir/config/source-profiles.json"}
check_dir=$(mktemp -d)
trap 'rm -rf "$check_dir"' EXIT
mkdir "$check_dir/cases"
if [[ $# -ge 2 ]]; then
  cp "$2" "$check_dir/cases/registry.json"
else
  printf '%s\n' '{"version":1,"cases":[]}' > "$check_dir/cases/registry.json"
fi
stack_version=$(python3 -c 'import builder; print(builder.init()["STACK_VERSION"])')
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=config-check \
  -keyout "$check_dir/key.pem" -out "$check_dir/ca.crt" >/dev/null 2>&1
chmod 755 "$check_dir"
chmod 644 "$check_dir/ca.crt"
chmod 755 "$check_dir/cases"
chmod 644 "$check_dir/cases/registry.json"
docker run --rm --network none --memory 1g \
  -e LOGSTASH_PASSWORD=configurationcheckonly \
  -e LS_JAVA_OPTS='-Xms256m -Xmx256m' \
  -v "$project_dir/config/logstash/logstash.yml:/usr/share/logstash/config/logstash.yml:ro" \
  -v "$project_dir/config/logstash/pipeline:/usr/share/logstash/pipeline:ro" \
  -v "$project_dir/config/logstash/normalize.rb:/usr/share/logstash/config/normalize.rb:ro" \
  -v "$project_dir/config/logstash/route.rb:/usr/share/logstash/config/route.rb:ro" \
  -v "$profile_config:/usr/share/logstash/config/source-profiles.json:ro" \
  -v "$check_dir/cases:/cases:ro" \
  -v "$check_dir/ca.crt:/usr/share/logstash/config/certs/ca/ca.crt:ro" \
  docker.elastic.co/logstash/logstash:"$stack_version" \
  --config.test_and_exit --path.data /tmp/config-check-data
