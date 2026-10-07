{{- define "aegis.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "aegis.labels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}
