<script setup>
import { computed, onMounted, ref } from 'vue'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Select from 'primevue/select'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import { getDiff, getLatestFindings, getScans, uploadTrivyReport } from './api'

const severities = ['Critical', 'High', 'Medium', 'Low']
const severityTag = { Critical: 'danger', High: 'warn', Medium: 'info', Low: 'success', Unknown: 'secondary' }

const scans = ref([])
const findings = ref([])
const minSeverity = ref(null)
const loading = ref(false)
const error = ref('')
const filters = ref({ global: { value: null, matchMode: 'contains' } })
const fileInput = ref(null)

// Diff state
const selectedDiffArtifact = ref(null)
const diffResult = ref(null)
const diffLoading = ref(false)
const diffError = ref('')
const activeDiffTab = ref('new')

const artifactOptions = computed(() => {
  const names = new Set(scans.value.map((s) => s.artifactName))
  return Array.from(names)
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    ;[scans.value, findings.value] = await Promise.all([getScans(), getLatestFindings(minSeverity.value)])
    if (selectedDiffArtifact.value) {
      await loadDiff(selectedDiffArtifact.value)
    } else if (scans.value.length > 0) {
      selectedDiffArtifact.value = scans.value[0].artifactName
      await loadDiff(scans.value[0].artifactName)
    }
  } catch (e) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

async function loadDiff(artifact) {
  if (!artifact) {
    diffResult.value = null
    return
  }
  diffLoading.value = true
  diffError.value = ''
  try {
    diffResult.value = await getDiff(artifact)
  } catch (e) {
    diffError.value = e.message
    diffResult.value = null
  } finally {
    diffLoading.value = false
  }
}

function selectArtifactForDiff(artifact) {
  selectedDiffArtifact.value = artifact
  loadDiff(artifact)
  const el = document.getElementById('diff-section')
  if (el) {
    el.scrollIntoView({ behavior: 'smooth' })
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

function getVulnerabilityUrl(id) {
  if (!id) return null
  if (id.startsWith('CVE-')) {
    return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`
  }
  if (id.startsWith('GHSA-')) {
    return `https://github.com/advisories/${encodeURIComponent(id)}`
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`
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

    <!-- Scans List -->
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
        <Column header="Diff" style="width: 6rem; text-align: center">
          <template #body="{ data }">
            <Button
              label="Diff"
              icon="pi pi-sliders-h"
              size="small"
              severity="secondary"
              outlined
              @click="selectArtifactForDiff(data.artifactName)"
            />
          </template>
        </Column>
      </DataTable>
    </section>

    <!-- Scan Diff Section -->
    <section id="diff-section" class="diff-section">
      <div class="section-header">
        <div>
          <h2><i class="pi pi-sliders-h" /> Scan Diff</h2>
          <p class="section-desc">Changes between the two most recent scans of an artifact.</p>
        </div>
        <div class="actions">
          <Select
            v-model="selectedDiffArtifact"
            :options="artifactOptions"
            placeholder="Select an artifact"
            style="min-width: 260px"
            @change="loadDiff(selectedDiffArtifact)"
          />
          <Button
            icon="pi pi-refresh"
            severity="secondary"
            outlined
            :disabled="!selectedDiffArtifact"
            aria-label="Refresh diff"
            @click="loadDiff(selectedDiffArtifact)"
          />
        </div>
      </div>

      <div v-if="diffLoading" class="diff-loading">
        <i class="pi pi-spin pi-spinner" /> Loading diff...
      </div>

      <p v-else-if="diffError" class="error">
        <i class="pi pi-exclamation-triangle" /> {{ diffError }}
      </p>

      <div v-else-if="diffResult" class="diff-content">
        <!-- Stat cards -->
        <div class="diff-stat-cards">
          <button
            type="button"
            class="stat-card stat-new"
            :class="{ active: activeDiffTab === 'new' }"
            @click="activeDiffTab = 'new'"
          >
            <div class="stat-count">{{ diffResult.newFindings?.length || 0 }}</div>
            <div class="stat-label">
              <i class="pi pi-plus-circle" /> New Findings
            </div>
            <span class="stat-hint">Introduced since previous scan</span>
          </button>

          <button
            type="button"
            class="stat-card stat-fixed"
            :class="{ active: activeDiffTab === 'fixed' }"
            @click="activeDiffTab = 'fixed'"
          >
            <div class="stat-count">{{ diffResult.fixedFindings?.length || 0 }}</div>
            <div class="stat-label">
              <i class="pi pi-check-circle" /> Fixed Findings
            </div>
            <span class="stat-hint">Resolved since previous scan</span>
          </button>

          <div class="stat-card stat-unchanged">
            <div class="stat-count">{{ diffResult.unchangedCount || 0 }}</div>
            <div class="stat-label">
              <i class="pi pi-minus-circle" /> Unchanged
            </div>
            <span class="stat-hint">Persisting across scans</span>
          </div>
        </div>

        <!-- Banner when only one scan exists -->
        <div v-if="!diffResult.previousScanId" class="info-banner">
          <i class="pi pi-info-circle" />
          <span>
            Only one scan found for <strong>{{ diffResult.artifactName }}</strong>. All findings are treated as new.
            Upload another scan of this artifact to track resolved issues!
          </span>
        </div>

        <!-- Diff Table Container -->
        <div class="diff-table-container">
          <div class="tab-header">
            <Button
              :label="`New Findings (${diffResult.newFindings?.length || 0})`"
              icon="pi pi-exclamation-circle"
              :severity="activeDiffTab === 'new' ? 'danger' : 'secondary'"
              :outlined="activeDiffTab !== 'new'"
              size="small"
              @click="activeDiffTab = 'new'"
            />
            <Button
              :label="`Fixed Findings (${diffResult.fixedFindings?.length || 0})`"
              icon="pi pi-check-circle"
              :severity="activeDiffTab === 'fixed' ? 'success' : 'secondary'"
              :outlined="activeDiffTab !== 'fixed'"
              size="small"
              @click="activeDiffTab = 'fixed'"
            />
          </div>

          <!-- New findings table -->
          <DataTable
            v-if="activeDiffTab === 'new'"
            :value="diffResult.newFindings"
            size="small"
            stripedRows
            paginator
            :rows="10"
          >
            <template #empty>
              <div class="table-empty-state">
                <i class="pi pi-check-circle" style="color: #16a34a" />
                <span>No new findings introduced in the latest scan!</span>
              </div>
            </template>
            <Column field="severity" header="Severity" sortable style="width: 7rem">
              <template #body="{ data }">
                <Tag :value="data.severity" :severity="severityTag[data.severity]" />
              </template>
            </Column>
            <Column field="vulnerabilityId" header="CVE" sortable style="width: 12rem">
              <template #body="{ data }">
                <a
                  v-if="getVulnerabilityUrl(data.vulnerabilityId)"
                  :href="getVulnerabilityUrl(data.vulnerabilityId)"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="cve-link"
                >
                  {{ data.vulnerabilityId }}
                  <i class="pi pi-external-link" />
                </a>
                <span v-else>{{ data.vulnerabilityId }}</span>
              </template>
            </Column>
            <Column field="packageName" header="Package" sortable style="width: 12rem" />
            <Column field="installedVersion" header="Installed" style="width: 10rem" />
            <Column field="fixedVersion" header="Fixed in" style="width: 10rem">
              <template #body="{ data }">{{ data.fixedVersion ?? '—' }}</template>
            </Column>
            <Column field="title" header="Title" />
          </DataTable>

          <!-- Fixed findings table -->
          <DataTable
            v-else
            :value="diffResult.fixedFindings"
            size="small"
            stripedRows
            paginator
            :rows="10"
          >
            <template #empty>
              <div class="table-empty-state">
                <i class="pi pi-info-circle" />
                <span>No fixed findings recorded in this scan.</span>
              </div>
            </template>
            <Column field="severity" header="Severity" sortable style="width: 7rem">
              <template #body="{ data }">
                <Tag :value="data.severity" :severity="severityTag[data.severity]" />
              </template>
            </Column>
            <Column field="vulnerabilityId" header="CVE" sortable style="width: 12rem">
              <template #body="{ data }">
                <a
                  v-if="getVulnerabilityUrl(data.vulnerabilityId)"
                  :href="getVulnerabilityUrl(data.vulnerabilityId)"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="cve-link"
                >
                  {{ data.vulnerabilityId }}
                  <i class="pi pi-external-link" />
                </a>
                <span v-else>{{ data.vulnerabilityId }}</span>
              </template>
            </Column>
            <Column field="packageName" header="Package" sortable style="width: 12rem" />
            <Column field="installedVersion" header="Previous Version" style="width: 10rem" />
            <Column field="fixedVersion" header="Fixed Version" style="width: 10rem">
              <template #body="{ data }">{{ data.fixedVersion ?? '—' }}</template>
            </Column>
            <Column field="title" header="Title" />
          </DataTable>
        </div>
      </div>

      <div v-else class="empty-diff-prompt">
        <p>Select an artifact to inspect changes between scans.</p>
      </div>
    </section>

    <!-- Latest Findings -->
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
        <Column field="vulnerabilityId" header="CVE" sortable>
          <template #body="{ data }">
            <a
              v-if="getVulnerabilityUrl(data.vulnerabilityId)"
              :href="getVulnerabilityUrl(data.vulnerabilityId)"
              target="_blank"
              rel="noopener noreferrer"
              class="cve-link"
            >
              {{ data.vulnerabilityId }}
              <i class="pi pi-external-link" />
            </a>
            <span v-else>{{ data.vulnerabilityId }}</span>
          </template>
        </Column>
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
