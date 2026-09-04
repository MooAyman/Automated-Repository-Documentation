{{/*
Expand the name of the chart.
*/}}
{{- define "{{ .Values.project.name }}.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "{{ .Values.project.name }}.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "{{ .Values.project.name }}.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "{{ .Values.project.name }}.labels" -}}
helm.sh/chart: {{ include "{{ .Values.project.name }}.chart" . }}
{{ include "{{ .Values.project.name }}.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
project: {{ .Values.project.name }}
{{- with .Values.labels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "{{ .Values.project.name }}.selectorLabels" -}}
app.kubernetes.io/name: {{ include "{{ .Values.project.name }}.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "{{ .Values.project.name }}.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "{{ .Values.project.name }}.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate image name
*/}}
{{- define "{{ .Values.project.name }}.image" -}}
{{- $registry := .Values.image.registry -}}
{{- $repository := .repository -}}
{{- $tag := .Values.image.tag -}}
{{- printf "%s/%s-%s:%s" $registry .Values.project.name $repository $tag }}
{{- end }}

{{/*
Generate model reference
*/}}
{{- define "{{ .Values.project.name }}.modelRef" -}}
{{- if .Values.models.azure.enabled }}
{{- .Values.models.azure.name }}
{{- else if .Values.models.openai.enabled }}
{{- .Values.models.openai.name }}
{{- else if .Values.models.anthropic.enabled }}
{{- .Values.models.anthropic.name }}
{{- else }}
default
{{- end }}
{{- end }}