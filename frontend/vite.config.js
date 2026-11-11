import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev only: proxy API + WebSocket to the Python backend. In production the
// backend serves the built files, so the app uses same-origin relative URLs.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': { target: 'http://127.0.0.1:8847', changeOrigin: true, ws: true } } },
  build: { outDir: 'dist', emptyOutDir: true, chunkSizeWarningLimit: 1200 },
})
