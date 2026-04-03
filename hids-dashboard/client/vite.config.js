import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      },
      '/api/upload': {
        target: 'http://localhost:5001',
        changeOrigin: true
      },
      '/api/process': {
        target: 'http://localhost:5001',
        changeOrigin: true
      }
    }
  }
})
