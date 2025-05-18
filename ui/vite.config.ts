import path from "path"
// Import defineConfig from vite
import { defineConfig, UserConfig } from 'vite'
// Import Vitest config type
import type { InlineConfig } from 'vitest'

/// <reference types="vitest" />
import react from '@vitejs/plugin-react'
// import tsconfigPaths from 'vite-tsconfig-paths'
import tailwindcss from '@tailwindcss/vite'

// Combine Vite and Vitest config types
interface VitestConfigExport extends UserConfig {
  test: InlineConfig
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // tsconfigPaths(),
    tailwindcss()
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, "./src"),
    }
  },
  server: {
    port: 5173,
  },
  // Vitest configuration
  test: {
    globals: true, // Use Vitest globals (describe, it, expect, etc.)
    environment: 'jsdom', // Simulate DOM environment
    setupFiles: [], // Optional: Add setup files if needed
    // reporters: ['verbose'] // Optional: Use verbose reporter
  },
} as VitestConfigExport) // Cast the config object
