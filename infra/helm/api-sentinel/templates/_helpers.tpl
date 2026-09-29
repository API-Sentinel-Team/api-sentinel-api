{{- define "api-sentinel.name" -}}
api-sentinel
{{- end -}}

{{- define "api-sentinel.fullname" -}}
{{- printf "%s" (include "api-sentinel.name" .) -}}
{{- end -}}

{{- define "api-sentinel.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- if .Values.serviceAccount.name -}}
{{ .Values.serviceAccount.name }}
{{- else -}}
{{ include "api-sentinel.fullname" . }}
{{- end -}}
{{- else -}}
default
{{- end -}}
{{- end -}}
