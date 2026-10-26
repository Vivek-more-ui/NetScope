
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// GitHub Pages repository path
const BASE_PATH = '/NetScope/';

// The API base URL can be overridden at build time with VITE_API_BASE_URL.
// In development, API requests use the local FastAPI backend.
const nodeEnv = (
  globalThis as unknown as {
    process?: { env?: Record<string, string | undefined> };
  }
).process?.env;

const API_TARGET =
  nodeEnv?.VITE_DEV_API_TARGET ?? 'http://127.0.0.1:8000';

export default defineConfig({
  // Required for deployment under https://vivek-more-ui.github.io/NetScope/
  base: BASE_PATH,

  plugins: [react()],

  server: {
    port: 5174,
    strictPort: true,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },

  preview: {
    port: 4173,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
      },
    },
  },

  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
