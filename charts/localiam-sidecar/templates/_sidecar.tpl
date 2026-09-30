{{/*
localiam-sidecar: container templates for localiam's two sidecars. A library
chart renders nothing on its own; include these from your own chart's pod
templates. See README.md for worked examples.

Every template takes one dict. Keys marked (required) fail rendering with a
message rather than producing a pod that cannot work.
*/}}

{{/* The image, pinned to this chart's appVersion unless overridden. */}}
{{- define "localiam-sidecar.image" -}}
{{- default "ghcr.io/blairham/localiam:0.0.0" .image }}
{{- end }}

{{- define "localiam-sidecar.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
localiam-sidecar.agent — the credential agent, one per workload pod.

  service              (required) the workload's name; selects its spec on the server
  roleArn              (required) role the issued credentials authenticate as
  server               (required) the localiam server's URL, e.g. http://localiam.localiam:8080
  registrationSecret   (required) {name, key} of a Secret holding the server's registration token
  image                default ghcr.io/blairham/localiam:0.0.0
  port                 loopback port for the Pod Identity contract, default 1338
  ttl                  credential lifetime, e.g. 2m; default 15m
  native               true renders a native sidecar (restartPolicy: Always) for
                       `initContainers`, so init containers get credentials too
                       (Kubernetes >= 1.29)
  resources            container resources
*/}}
{{- define "localiam-sidecar.agent" -}}
{{- $secret := required "localiam-sidecar.agent: registrationSecret {name, key} is required" .registrationSecret -}}
- name: localiam-agent
  image: {{ include "localiam-sidecar.image" . }}
  {{- if .native }}
  restartPolicy: Always
  {{- end }}
  args:
    - agent
    - -service={{ required "localiam-sidecar.agent: service is required" .service }}
    - -role-arn={{ required "localiam-sidecar.agent: roleArn is required" .roleArn }}
    - -listen=127.0.0.1:{{ default 1338 .port }}
    {{- with .ttl }}
    - -ttl={{ . }}
    {{- end }}
  env:
    - name: LOCALIAM_REGISTER_URL
      value: {{ required "localiam-sidecar.agent: server is required" .server | quote }}
    - name: LOCALIAM_REGISTER_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ required "localiam-sidecar.agent: registrationSecret.name is required" $secret.name }}
          key: {{ default "register-token" $secret.key }}
  securityContext:
    {{- include "localiam-sidecar.securityContext" . | nindent 4 }}
  {{- with .resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}

{{/*
localiam-sidecar.workloadEnv — env entries for the workload container, pointing
its AWS SDK at the agent exactly as EKS Pod Identity would.

  port     the agent's port, default 1338
  region   sets AWS_REGION when given
*/}}
{{- define "localiam-sidecar.workloadEnv" -}}
- name: AWS_CONTAINER_CREDENTIALS_FULL_URI
  value: http://127.0.0.1:{{ default 1338 .port }}/v1/credentials
- name: AWS_CONTAINER_AUTHORIZATION_TOKEN
  value: localiam
{{- with .region }}
- name: AWS_REGION
  value: {{ . | quote }}
{{- end }}
{{- end }}

{{/*
localiam-sidecar.proxy — auth-terminating proxies, in the STORE's pod, in
front of a store that listens on loopback with authentication disabled. Give
any of redis, postgres, kafka; at least one is required.

  server     (required) the localiam server's URL
  image      default ghcr.io/blairham/localiam:0.0.0
  redis      {port: 6379, backend: 127.0.0.1:6380, replicationGroup (required)}
  postgres   {port: 5432, backend: 127.0.0.1:5433, host (required), signedPort: 5432}
             host/signedPort are what CLIENTS are configured with — their
             tokens are signed over it
  kafka      {port: 9094, backend: 127.0.0.1:9095, host (required), tlsSecret}
             tlsSecret names a Secret with server.pem and server-key.pem
             (from `localiam gen-certs`), mounted via
             localiam-sidecar.kafkaTLSVolume
  resources  container resources
*/}}
{{- define "localiam-sidecar.proxy" -}}
{{- if not (or .redis .postgres .kafka) }}
{{- fail "localiam-sidecar.proxy: give at least one of redis, postgres, kafka" }}
{{- end -}}
- name: localiam-proxy
  image: {{ include "localiam-sidecar.image" . }}
  args:
    - proxy
    {{- with .redis }}
    - -redis-listen=:{{ default 6379 .port }}
    - -redis-backend={{ default "127.0.0.1:6380" .backend }}
    - -redis-replication-group={{ required "localiam-sidecar.proxy: redis.replicationGroup is required" .replicationGroup }}
    {{- end }}
    {{- with .postgres }}
    - -pg-listen=:{{ default 5432 .port }}
    - -pg-backend={{ default "127.0.0.1:5433" .backend }}
    - -pg-host={{ required "localiam-sidecar.proxy: postgres.host is required (the host clients dial)" .host }}
    - -pg-port={{ default 5432 .signedPort }}
    {{- end }}
    {{- with .kafka }}
    - -kafka-listen=:{{ default 9094 .port }}
    - -kafka-backend={{ default "127.0.0.1:9095" .backend }}
    - -kafka-host={{ required "localiam-sidecar.proxy: kafka.host is required (the name clients dial)" .host }}
    {{- if .tlsSecret }}
    - -kafka-tls-cert=/etc/localiam/kafka-tls/server.pem
    - -kafka-tls-key=/etc/localiam/kafka-tls/server-key.pem
    {{- end }}
    {{- end }}
  env:
    - name: LOCALIAM_VERIFY_URL
      value: {{ required "localiam-sidecar.proxy: server is required" .server | quote }}
  ports:
    {{- with .redis }}
    - name: redis
      containerPort: {{ default 6379 .port }}
    {{- end }}
    {{- with .postgres }}
    - name: postgres
      containerPort: {{ default 5432 .port }}
    {{- end }}
    {{- with .kafka }}
    - name: kafka
      containerPort: {{ default 9094 .port }}
    {{- end }}
  {{- if and .kafka .kafka.tlsSecret }}
  volumeMounts:
    - name: localiam-kafka-tls
      mountPath: /etc/localiam/kafka-tls
      readOnly: true
  {{- end }}
  securityContext:
    {{- include "localiam-sidecar.securityContext" . | nindent 4 }}
  {{- with .resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}

{{/*
localiam-sidecar.kafkaTLSVolume — the volume the Kafka proxy mounts. Add it to
the pod's volumes when the proxy is given kafka.tlsSecret.

  secretName  (required) Secret with server.pem and server-key.pem
*/}}
{{- define "localiam-sidecar.kafkaTLSVolume" -}}
- name: localiam-kafka-tls
  secret:
    secretName: {{ required "localiam-sidecar.kafkaTLSVolume: secretName is required" .secretName }}
{{- end }}
