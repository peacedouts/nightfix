{{- define "nightfix-agent.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "nightfix-agent.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "nightfix-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "nightfix-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "nightfix-agent.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The image, refused unless pinned by digest. */}}
{{- define "nightfix-agent.image" -}}
{{- $d := required "image.digest is required (sha256:<64 hex>): tags can be re-pushed, so the agent is pinned by digest" .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $d) -}}
{{- fail "image.digest must be sha256:<64 hex digits>" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository $d -}}
{{- end -}}
