import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],

  build: {
    // Raise the warning limit (our app is intentionally large for now)
    chunkSizeWarningLimit: 600,

    rollupOptions: {
      output: {
        // Manual chunk splitting: move heavy vendor libs into separate cacheable chunks.
        // This means Firebase, React, Lucide etc. are loaded once and cached by the browser.
        manualChunks(id) {
          // Firebase SDK — very large, rarely changes
          if (id.includes('node_modules/firebase') || id.includes('node_modules/@firebase')) {
            return 'vendor-firebase';
          }
          // Lucide icons
          if (id.includes('node_modules/lucide-react')) {
            return 'vendor-icons';
          }
          // EmailJS
          if (id.includes('node_modules/@emailjs')) {
            return 'vendor-emailjs';
          }
          // React core
          if (id.includes('node_modules/react') || id.includes('node_modules/react-dom') || id.includes('node_modules/react-router-dom')) {
            return 'vendor-react';
          }
        }
      }
    }
  },

  // Enable dependency pre-bundling to speed up cold starts in dev
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'firebase/app',
      'firebase/auth',
      'lucide-react',
      '@emailjs/browser'
    ]
  },

  server: {
    // Proxy API calls in dev so the browser doesn't have to handle CORS
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
