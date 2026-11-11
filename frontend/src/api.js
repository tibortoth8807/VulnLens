// Thin wrapper around the VulnLens API. Relative URLs: Vite proxy in dev, nginx proxy in Docker.

async function request(url, options) {
  const response = await fetch(url, options)
  if (!response.ok) {
    const problem = await response.json().catch(() => null)
    throw new Error(problem?.detail ?? `${response.status} ${response.statusText}`)
  }
  return response.json()
}

export const getScans = () => request('/api/scans')

export const getLatestFindings = (minSeverity) =>
  request(`/api/findings${minSeverity ? `?minSeverity=${encodeURIComponent(minSeverity)}` : ''}`)

export const getDiff = (artifact) => request(`/api/diff?artifact=${encodeURIComponent(artifact)}`)

export const uploadTrivyReport = (file) =>
  request('/api/scans/trivy', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: file,
  })
