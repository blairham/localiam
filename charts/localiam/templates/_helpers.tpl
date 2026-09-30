{{/* Expand the name of the chart. */}}
{{- define "localiam.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, capped at 63 characters because some Kubernetes name
fields are limited to that.
*/}}
{{- define "localiam.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "localiam.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "localiam.labels" -}}
helm.sh/chart: {{ include "localiam.chart" . }}
{{ include "localiam.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: server
{{- with .Values.additionalLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "localiam.selectorLabels" -}}
app.kubernetes.io/name: {{ include "localiam.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "localiam.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "localiam.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "localiam.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* The Secret holding the registration token. */}}
{{- define "localiam.registrationSecret" -}}
{{- default (include "localiam.fullname" .) .Values.registration.existingSecret }}
{{- end }}

{{/*
The registration token to write into the chart's Secret: the value given, else
the one already in the cluster (so an upgrade does not rotate it and orphan
every agent), else a new random one.
*/}}
{{- define "localiam.registrationToken" -}}
{{- if .Values.registration.token }}
{{- .Values.registration.token }}
{{- else }}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "localiam.fullname" .) }}
{{- if and $existing (index $existing.data .Values.registration.secretKey) }}
{{- index $existing.data .Values.registration.secretKey | b64dec }}
{{- else }}
{{- randAlphaNum 32 }}
{{- end }}
{{- end }}
{{- end }}

{{- define "localiam.shellSecret" -}}
{{- default (printf "%s-shell" (include "localiam.fullname" .)) .Values.shell.existingSecret }}
{{- end }}

{{- define "localiam.specsConfigMap" -}}
{{- default (printf "%s-specs" (include "localiam.fullname" .)) .Values.existingSpecsConfigMap }}
{{- end }}

{{- define "localiam.hasSpecs" -}}
{{- if or .Values.existingSpecsConfigMap .Values.specs }}true{{ end }}
{{- end }}
