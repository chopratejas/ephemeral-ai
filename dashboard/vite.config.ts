import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',  // Relative paths so it works from any folder (Spaces, CDN, etc.)
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
