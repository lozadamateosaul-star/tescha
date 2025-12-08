import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0', // Escucha en todas las interfaces
    allowedHosts: [
      'localhost',
      'coordinacion-tescha.local',
      '.local' // Permite todos los dominios .local
    ],
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true
      }
    }
  }
})
