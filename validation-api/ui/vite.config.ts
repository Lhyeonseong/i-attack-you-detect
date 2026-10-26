/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// 운영 CSP: default-src 'self'; script-src 'self'(unsafe-eval 없음); style-src 'self'; img-src 'self' data:
// - 외부 CDN 미사용(글꼴은 @fontsource 자체 호스팅).
// - vega-lite 는 AST 인터프리터로 평가하여 unsafe-eval 불필요.
export default defineConfig({
  plugins: [react()],
  build: {
    target: 'es2022',
    // 인라인 스크립트/스타일을 만들지 않도록 자산을 외부 파일로 유지(CSP script-src/style-src 'self' 호환).
    assetsInlineLimit: 0,
    cssCodeSplit: true,
  },
  server: {
    // 개발 중에는 mock 을 사용(import.meta.env.DEV). 실제 백엔드로 붙이려면 proxy 활성화.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: 'node',
    globals: true,
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
