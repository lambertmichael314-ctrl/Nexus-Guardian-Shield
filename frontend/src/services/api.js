import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
})

// Attach access token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle 401 by attempting refresh, then redirect to login on failure
api.interceptors.response.use(
  (res) => res,
  async (err) => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
      original._retry = true
      const refresh = localStorage.getItem('refresh_token')
      if (refresh) {
        try {
          const { data } = await axios.post(`${API_BASE}/auth/refresh`, {
            refresh_token: refresh,
          })
          localStorage.setItem('access_token', data.access_token)
          localStorage.setItem('refresh_token', data.refresh_token)
          original.headers.Authorization = `Bearer ${data.access_token}`
          return api(original)
        } catch (_) {
          localStorage.removeItem('access_token')
          localStorage.removeItem('refresh_token')
          window.location.href = '/login'
        }
      } else {
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

// ─── Auth endpoints ───
export const login = (username, password) =>
  api.post('/auth/login', { username, password })

export const register = (payload) =>
  api.post('/auth/register', payload)

export const getMe = () =>
  api.get('/auth/me')

// ─── Users ───
export const listUsers = (params) =>
  api.get('/users/', { params })

export const getUser = (id) =>
  api.get(`/users/${id}`)

export const createUser = (payload) =>
  api.post('/users/', payload)

export const updateUser = (id, payload) =>
  api.put(`/users/${id}`, payload)

export const deleteUser = (id) =>
  api.delete(`/users/${id}`)

// ─── Intelligence (IOCs) ───
export const listIOCs = (params) =>
  api.get('/intelligence/', { params })

export const createIOC = (payload) =>
  api.post('/intelligence/', payload)

export const createIOCsBulk = (indicators) =>
  api.post('/intelligence/bulk', { indicators })

export const getIOC = (id) =>
  api.get(`/intelligence/${id}`)

export const updateIOC = (id, payload) =>
  api.put(`/intelligence/${id}`, payload)

export const deleteIOC = (id) =>
  api.delete(`/intelligence/${id}`)

// ─── Analysis ───
export const uploadSample = (file, notes) => {
  const form = new FormData()
  form.append('file', file)
  const qs = notes ? `?notes=${encodeURIComponent(notes)}` : ''
  // Delete the default JSON Content-Type so browser sets multipart boundary
  return api.post(`/analysis/upload${qs}`, form, {
    headers: { 'Content-Type': undefined }
  })
}

export const getScan = (id) =>
  api.get(`/analysis/jobs/${id}`)

export const listScans = (params) =>
  api.get('/analysis/jobs', { params })

export const listYaraRules = () =>
  api.get('/analysis/yara/rules')

export default api
