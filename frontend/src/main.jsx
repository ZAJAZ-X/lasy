import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

try { const u = JSON.parse(localStorage.getItem('lasy_ui') || '{}'); document.documentElement.dataset.size = u.size || 'large'; document.documentElement.dataset.style = u.style || 'glass' } catch { document.documentElement.dataset.size = 'large'; document.documentElement.dataset.style = 'glass' }

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
