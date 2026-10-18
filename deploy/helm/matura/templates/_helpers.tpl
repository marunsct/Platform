{{- define "matura.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{ else }}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{ end }}
{{- end }}

{{- define "matura.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "matura.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "matura.issuer" -}}
{{- .Values.keycloak.issuer | default (printf "%s/realms/matura" (trimSuffix "/" .Values.keycloak.hostname)) }}
{{- end }}

{{- define "matura.dbSecret" -}}
{{- .Values.database.existingSecret | default (printf "%s-db" (include "matura.fullname" .)) }}
{{- end }}

{{- define "matura.secrets" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" (include "matura.fullname" .)) }}
{{- end }}
