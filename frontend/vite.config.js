import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In dev, Vite proxies API calls to the .NET backend, so no CORS setup is needed.
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      '/health': 'http://localhost:8080',
    },
  },
})
