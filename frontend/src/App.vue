<script setup>
import { onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { getLatestFindings, getScans, uploadTrivyReport } from './api'

const severities = ['Critical', 'High', 'Medium', 'Low']
const severityTag = { Critical: 'danger', High: 'warn', Medium: 'info', Low: 'success', Unknown: 'secondary' }

const scans = ref([])
const findings = ref([])
const minSeverity = ref(null)
const loading = ref(false)
const error = ref('')
const filters = ref({ global: { value: null, matchMode: 'contains' } })
const fileInput = ref(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    ;[scans.value, findings.value] = await Promise.all([getScans(), getLatestFindings(minSeverity.value)])
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function onFileSelected(event) {
  const file = event.target.files?.[0]
  if (!file) return
  try {
    await uploadTrivyReport(file)
    await load()
  } catch (e) {
    error.value = e.message
  } finally {
    event.target.value = ''
  }
}

const formatDate = (value) => new Date(value).toLocaleString()

onMounted(load)
</script>

<template>
  <main class="layout">
    <header class="header">
      <div>
        <h1><i class="pi pi-shield" /> VulnLens</h1>
        <p class="subtitle">Vulnerability scan aggregator for container images</p>
      </div>
      <div class="actions">
        <input ref="fileInput" type="file" accept=".json" hidden @change="onFileSelected" />
        <Button label="Upload Trivy report" icon="pi pi-upload" @click="fileInput.click()" />
        <Button icon="pi pi-refresh" severity="secondary" aria-label="Refresh" @click="load" />
      </div>
    </header>

    <p v-if="error" class="error"><i class="pi pi-exclamation-triangle" /> {{ error }}</p>

    <section>
      <h2>Scans</h2>
      <DataTable :value="scans" :loading="loading" size="small" stripedRows>
        <template #empty>No scans yet. Upload a Trivy JSON report to get started.</template>
        <Column field="artifactName" header="Artifact" />
        <Column field="scannedAt" header="Scanned" sortable>
          <template #body="{ data }">{{ formatDate(data.scannedAt) }}</template>
        </Column>
        <Column header="Critical"><template #body="{ data }">{{ data.counts.critical }}</template></Column>
        <Column header="High"><template #body="{ data }">{{ data.counts.high }}</template></Column>
        <Column header="Medium"><template #body="{ data }">{{ data.counts.medium }}</template></Column>
        <Column header="Low"><template #body="{ data }">{{ data.counts.low }}</template></Column>
        <Column field="totalFindings" header="Total" sortable />
      </DataTable>
    </section>

    <section>
      <div class="section-header">
        <h2>Latest findings</h2>
        <div class="actions">
          <Select v-model="minSeverity" :options="severities" placeholder="Min. severity" showClear @change="load" />
          <InputText v-model="filters.global.value" placeholder="Search CVE / package" />
        </div>
      </div>
      <DataTable
        :value="findings"
        :loading="loading"
        v-model:filters="filters"
        :globalFilterFields="['vulnerabilityId', 'packageName', 'artifactName', 'title']"
        paginator
        :rows="15"
        size="small"
        sortMode="multiple"
        stripedRows
      >
        <template #empty>No findings.</template>
        <Column field="severity" header="Severity" sortable>
          <template #body="{ data }"><Tag :value="data.severity" :severity="severityTag[data.severity]" /></template>
        </Column>
        <Column field="vulnerabilityId" header="CVE" sortable />
        <Column field="packageName" header="Package" sortable />
        <Column field="installedVersion" header="Installed" />
        <Column field="fixedVersion" header="Fixed in">
          <template #body="{ data }">{{ data.fixedVersion ?? '—' }}</template>
        </Column>
        <Column field="artifactName" header="Artifact" sortable />
        <Column field="title" header="Title" />
      </DataTable>
    </section>
  </main>
</template>
