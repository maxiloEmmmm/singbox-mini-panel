import type { App as VueApp, Plugin } from 'vue'
import { createApp } from 'vue'
import Alert from 'ant-design-vue/es/alert'
import Button from 'ant-design-vue/es/button'
import Form from 'ant-design-vue/es/form'
import Input from 'ant-design-vue/es/input'
import Modal from 'ant-design-vue/es/modal'
import Segmented from 'ant-design-vue/es/segmented'
import Select from 'ant-design-vue/es/select'
import Switch from 'ant-design-vue/es/switch'
import Tabs from 'ant-design-vue/es/tabs'
import Tag from 'ant-design-vue/es/tag'
import App from './App.vue'
import 'ant-design-vue/dist/reset.css'
import './style.css'

const antComponents = [
  Alert,
  Button,
  Form,
  Input,
  Modal,
  Segmented,
  Select,
  Switch,
  Tabs,
  Tag,
] as Plugin[]

// 适用场景：按需安装当前页面实际使用的 Ant Design Vue 组件。
function installAntComponent(app: VueApp, component: Plugin) {
  app.use(component)
}

// 适用场景：把根组件挂载到静态 HTML 容器。
function mountApp() {
  const app = createApp(App)
  for (const component of antComponents) {
    installAntComponent(app, component)
  }

  app.mount('#app')
}

mountApp()
