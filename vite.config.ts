import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 适用场景：给本地 Vue 单页靶场提供 Vite 开发与构建配置。
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'sboxctl/web/dist',
    emptyOutDir: true,
    target: 'es2022',
  },
})
