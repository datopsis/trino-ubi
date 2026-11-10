#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C
umask 0027
fail() { printf 'trino-entrypoint: %s\n' "$*" >&2; exit 1; }
[[ $EUID != 0 ]] || fail 'refusing root; run as UID 10001'
[[ $# == 0 ]] || fail 'arguments are not supported; mount configuration at /etc/trino'
[[ -z ${JAVA_TOOL_OPTIONS:-}${JDK_JAVA_OPTIONS:-}${_JAVA_OPTIONS:-} ]] || fail 'Java option environment overrides are forbidden'
case ${TRINO_UBI_ALLOW_INSECURE:-false} in true|false) ;; *) fail 'TRINO_UBI_ALLOW_INSECURE must be true or false' ;; esac
heap=${TRINO_HEAP_SIZE:-1G}
[[ $heap =~ ^[1-9][0-9]*[MG]$ ]] || fail 'TRINO_HEAP_SIZE must be an integer followed by M or G'

# Deliberately restricted Java-properties syntax: no escapes, continuations,
# interpolation or duplicate keys. This keeps guard and JVM interpretations equal.
declare -A config node auth
read_properties() {
    local file=$1 line key value
    local -n properties=$2
    [[ -s $file && -r $file ]] || fail "missing or unreadable configuration: $file"
    [[ ! -w $file ]] || fail "configuration must be read-only: $file"
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -z $line || $line == \#* ]] && continue
        [[ $line =~ ^([a-zA-Z0-9_.-]+)=(.*)$ ]] || fail "invalid key=value configuration: $file"
        key=${BASH_REMATCH[1]}; value=${BASH_REMATCH[2]}
        [[ $value != *\\* && $value != *"\${"* && $value != *[[:cntrl:]]* ]] || fail "unsupported escape or interpolation: $file ($key)"
        [[ ! -v properties[$key] ]] || fail "duplicate property: $file ($key)"
        # Nameref targets a declared associative array, not an arithmetic index.
        # shellcheck disable=SC2004
        properties[$key]=$value
    done < "$file"
}
read_properties /etc/trino/config.properties config
read_properties /etc/trino/node.properties node
[[ -r /etc/trino/log.properties ]] || fail 'missing /etc/trino/log.properties'
[[ -s /etc/trino/catalog/tpch.properties ]] || fail 'missing /etc/trino/catalog/tpch.properties'
[[ ${node[node.data-dir]:-} == /var/lib/trino ]] || fail 'node.data-dir must be /var/lib/trino'
[[ -n ${node[node.environment]:-} && -n ${node[node.id]:-} ]] || fail 'node.environment and node.id are required'
[[ ${config[coordinator]:-} == true && ${config[node-scheduler.include-coordinator]:-} == true ]] || fail 'first increment requires coordinator=true and node-scheduler.include-coordinator=true'
for key in http-server.http.port http-server.https.port; do
    port=${config[$key]:-}
    [[ -z $port ]] && continue
    if [[ ! $port =~ ^[0-9]{4,5}$ ]] || ((10#$port < 1024 || 10#$port > 65535)); then
        fail "$key must be an unprivileged port"
    fi
done
node_options=()
for key in "${!node[@]}"; do
    [[ $key == node.* ]] || fail "node.properties permits only node.* keys"
    node_options+=("-D$key=${node[$key]}")
done
# All mutable state is explicit. Missing mounts fail before starting Java.
for path in /var/lib/trino /tmp/trino; do
    [[ -d $path ]] || fail "missing writable path: $path"
    ( : > "$path/.write-probe" ) 2>/dev/null || fail "mount a writable volume or tmpfs at $path"
    rm "$path/.write-probe"
done
secret_file() {
    local file=$1 mode
    [[ $file == /* && -s $file && -r $file && ! -w $file ]] || fail "missing or non-read-only secret file: $file"
    mode=$(stat -c '%a' "$file")
    (( (8#$mode & 7) == 0 )) || fail "secret file must not be world-accessible: $file"
}
if [[ ${TRINO_UBI_ALLOW_INSECURE:-false} != true ]]; then
    [[ ${config[http-server.authentication.type]:-} == PASSWORD ]] || fail 'authentication required: configure PASSWORD with TLS, or explicitly set TRINO_UBI_ALLOW_INSECURE=true for isolated tests'
    [[ ${config[http-server.http.enabled]:-} == false && ${config[http-server.https.enabled]:-} == true ]] || fail 'authenticated mode requires HTTPS enabled and HTTP disabled'
    [[ ${config[http-server.https.port]:-} == 8443 ]] || fail 'authenticated mode requires HTTPS port 8443'
    [[ ${config[http-server.authentication.allow-insecure-over-http]:-false} == false ]] || fail 'insecure HTTP authentication is forbidden'
    [[ ${config[internal-communication.https.required]:-} == true ]] || fail 'internal-communication.https.required=true is required'
    [[ -n ${config[internal-communication.shared-secret]:-} ]] || fail 'internal-communication.shared-secret is required in read-only configuration'
    [[ ${config[discovery.uri]:-} == https://* ]] || fail 'authenticated mode requires HTTPS discovery.uri'
    secret_file /etc/trino/config.properties
    secret_file "${config[http-server.https.keystore.path]:-missing-keystore}"
    read_properties /etc/trino/password-authenticator.properties auth
    [[ ${auth[password-authenticator.name]:-} == file ]] || fail 'first increment supports the file password authenticator'
    secret_file "${auth[file.password-file]:-missing-password-file}"
else
    printf 'WARNING: explicit insecure test mode; authentication and TLS are deployment responsibilities. Do not expose this listener.\n' >&2
fi
# Match upstream foreground launcher properties without shipping daemon launchers.
# Java is PID 1, inherits the non-root identity, and receives SIGTERM directly.
exec /opt/java/bin/java -server "-Xmx$heap" \
    -XX:+ExitOnOutOfMemoryError -XX:-OmitStackTraceInFastThrow \
    -XX:+ExplicitGCInvokesConcurrent -XX:ReservedCodeCacheSize=256M \
    -XX:ActiveProcessorCount=2 -XX:+EnableDynamicAgentLoading \
    -XX:+UseCompactObjectHeaders -XX:-RewriteBytecodes \
    -Djdk.attach.allowAttachSelf=true -Djdk.nio.maxCachedBufferSize=2000000 \
    -Djava.io.tmpdir=/tmp/trino -Duser.home=/var/lib/trino \
    --enable-native-access=ALL-UNNAMED --add-modules=jdk.incubator.vector \
    --sun-misc-unsafe-memory-access=allow \
    "${node_options[@]}" -Dconfig=/etc/trino/config.properties \
    -Dlog.levels-file=/etc/trino/log.properties -Dlog.enable-console=true \
    -cp '/opt/trino/lib/*' io.trino.server.TrinoServer
