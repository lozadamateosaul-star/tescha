import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Interceptor para agregar token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Interceptor para manejar errores
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Solo limpiar el localStorage, el AuthContext manejará la redirección
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      // Recargar la página para que AuthContext detecte que no hay sesión
      if (!window.location.pathname.includes('/login')) {
        window.location.reload();
      }
    }
    return Promise.reject(error);
  }
);

export default api;

// Servicios de API
export const authService = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
  getProfile: () => api.get('/auth/me'),
  changePassword: (passwords) => api.put('/auth/change-password', passwords)
};

export const alumnosService = {
  getAll: (params) => api.get('/alumnos', { params }),
  getById: (id) => api.get(`/alumnos/${id}`),
  create: (data) => api.post('/alumnos', data),
  update: (id, data) => api.put(`/alumnos/${id}`, data),
  delete: (id) => api.delete(`/alumnos/${id}`),
  getHistorial: (id) => api.get(`/alumnos/${id}/historial`),
  importar: (data) => api.post('/alumnos/import', data)
};

export const maestrosService = {
  getAll: () => api.get('/maestros'),
  getById: (id) => api.get(`/maestros/${id}`),
  create: (data) => api.post('/maestros', data),
  update: (id, data) => api.put(`/maestros/${id}`, data),
  delete: (id) => api.delete(`/maestros/${id}`),
  getHorarios: (id) => api.get(`/maestros/${id}/horarios`),
  toggleStatus: (id) => api.patch(`/maestros/${id}/toggle-status`),
  resetPassword: (id) => api.post(`/maestros/${id}/reset-password`)
};

export const gruposService = {
  getAll: (params) => api.get('/grupos', { params }),
  getById: (id) => api.get(`/grupos/${id}`),
  create: (data) => api.post('/grupos', data),
  update: (id, data) => api.put(`/grupos/${id}`, data),
  delete: (id) => api.delete(`/grupos/${id}`),
  inscribir: (id, data) => api.post(`/grupos/${id}/inscribir`, data),
  getAlumnos: (id) => api.get(`/grupos/${id}/alumnos`)
};

export const salonesService = {
  getAll: (params) => api.get('/salones', { params }),
  getById: (id) => api.get(`/salones/${id}`),
  create: (data) => api.post('/salones', data),
  update: (id, data) => api.put(`/salones/${id}`, data),
  delete: (id) => api.delete(`/salones/${id}`),
  verificarDisponibilidad: (data) => api.post('/salones/verificar-disponibilidad', data),
  getHorario: (id) => api.get(`/salones/${id}/horario`),
  sugerir: (data) => api.post('/salones/sugerir', data),
  getMapaOcupacion: (params) => api.get('/salones/mapa/ocupacion', { params })
};

export const periodosService = {
  getAll: () => api.get('/periodos'),
  getActivo: () => api.get('/periodos/activo'),
  create: (data) => api.post('/periodos', data),
  update: (id, data) => api.put(`/periodos/${id}`, data),
  delete: (id) => api.delete(`/periodos/${id}`),
  toggle: (id, activo) => api.patch(`/periodos/${id}/toggle`, { activo }),
  configurarTarifas: (id, data) => api.post(`/periodos/${id}/tarifas`, data),
  getTarifas: (id) => api.get(`/periodos/${id}/tarifas`)
};

export const pagosService = {
  getAll: (params) => api.get('/pagos', { params }),
  create: (data) => api.post('/pagos', data),
  update: (id, data) => api.put(`/pagos/${id}`, data),
  updateEstatus: (id, estatus) => api.put(`/pagos/${id}/estatus`, { estatus }),
  solicitarProrroga: (data) => api.post('/pagos/prorrogas', data),
  gestionarProrroga: (id, data) => api.put(`/pagos/prorrogas/${id}`, data),
  getProrrogas: (params) => api.get('/pagos/prorrogas', { params }),
  getReporteAdeudos: (params) => api.get('/pagos/reportes/adeudos', { params }),
  getReporteIngresos: (params) => api.get('/pagos/reportes/ingresos', { params }),
  getReporteProrrogasActivas: () => api.get('/pagos/reportes/prorrogas-activas'),
  getReporteAdeudosCriticos: () => api.get('/pagos/reportes/adeudos-criticos')
};

export const calificacionesService = {
  getByGrupo: (grupoId, parcial) => api.get(`/calificaciones/grupo/${grupoId}`, { params: { parcial } }),
  create: (data) => api.post('/calificaciones', data),
  saveMultiple: (data) => api.post('/calificaciones/masivo', data),
  createMasivo: (data) => api.post('/calificaciones/masivo', data),
  getByAlumno: (alumnoId) => api.get(`/calificaciones/alumno/${alumnoId}`),
  getReprobados: (grupoId) => api.get(`/calificaciones/grupo/${grupoId}/reprobados`)
};

export const asistenciasService = {
  create: (data) => api.post('/asistencias', data),
  saveMultiple: (data) => api.post('/asistencias/masivo', data),
  createMasivo: (data) => api.post('/asistencias/masivo', data),
  getByGrupo: (grupoId, params) => api.get(`/asistencias/grupo/${grupoId}`, { params }),
  getByGrupoFecha: (grupoId, fecha) => api.get(`/asistencias/grupo/${grupoId}`, { params: { fecha } }),
  getByAlumno: (alumnoId, params) => api.get(`/asistencias/alumno/${alumnoId}`, { params }),
  getEnRiesgo: (grupoId) => api.get(`/asistencias/grupo/${grupoId}/riesgo`)
};

export const librosService = {
  getAll: (params) => api.get('/libros', { params }),
  create: (data) => api.post('/libros', data),
  update: (id, data) => api.put(`/libros/${id}`, data),
  delete: (id) => api.delete(`/libros/${id}`),
  vender: (data) => api.post('/libros/ventas', data),
  getVentas: (params) => api.get('/libros/ventas', { params }),
  getReporteVentas: (params) => api.get('/libros/reportes/ventas', { params })
};

export const dashboardService = {
  getStats: () => api.get('/dashboard'),
  getByPeriodo: (periodoId) => api.get(`/dashboard/periodo/${periodoId}`),
  getTendencias: () => api.get('/dashboard/tendencias')
};

export const reportesService = {
  getReprobacion: (params) => api.get('/reportes/reprobacion', { params }),
  getDesercion: (params) => api.get('/reportes/desercion', { params }),
  getOcupacionSalones: (params) => api.get('/reportes/salones/ocupacion', { params }),
  getAlumnosSinRequisito: () => api.get('/reportes/alumnos/sin-requisito'),
  getCargaMaestros: () => api.get('/reportes/maestros/carga'),
  getEficienciaTerminal: (params) => api.get('/reportes/eficiencia-terminal', { params }),
  getProrrogasActivas: () => api.get('/pagos/reportes/prorrogas-activas'),
  getAdeudosCriticos: () => api.get('/pagos/reportes/adeudos-criticos'),
  exportar: (tipo, params) => api.get(`/reportes/exportar/${tipo}`, {
    params,
    responseType: 'blob' // Importante: para recibir archivos binarios
  })
};

export const maestroDashboardService = {
  getMisGrupos: () => api.get('/maestros-dashboard/mis-grupos'),
  getAlumnosGrupo: (grupoId) => api.get(`/maestros-dashboard/alumnos-grupo/${grupoId}`),
  descargarPlantillaCalificaciones: (grupoId, parcial) =>
    api.get(`/maestros-dashboard/plantilla-calificaciones/${grupoId}/${parcial}`, { responseType: 'blob' }),
  descargarPlantillaAsistencias: (grupoId, fecha) =>
    api.get(`/maestros-dashboard/plantilla-asistencias/${grupoId}/${fecha}`, { responseType: 'blob' })
};

export const maestrosAlumnosService = {
  getGruposConAlumnos: (maestroId) => api.get(`/maestros-alumnos/${maestroId}/grupos-alumnos`),
  getAlumnosGrupo: (maestroId, grupoId) => api.get(`/maestros-alumnos/${maestroId}/grupos/${grupoId}/alumnos`),
  getAlumnosDisponibles: (maestroId, grupoId) => api.get(`/maestros-alumnos/${maestroId}/grupos/${grupoId}/disponibles`),
  inscribirAlumno: (maestroId, grupoId, alumnoId) => api.post(`/maestros-alumnos/${maestroId}/grupos/${grupoId}/inscribir`, { alumnoId }),
  removerAlumno: (maestroId, grupoId, inscripcionId) => api.delete(`/maestros-alumnos/${maestroId}/grupos/${grupoId}/alumnos/${inscripcionId}`)
};

export const uploadService = {
  procesarCalificaciones: (formData) =>
    api.post('/upload/procesar-calificaciones', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }),
  guardarCalificaciones: (data) => api.post('/upload/guardar-calificaciones', data),
  procesarAsistencias: (formData) =>
    api.post('/upload/procesar-asistencias', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    }),
  guardarAsistencias: (data) => api.post('/upload/guardar-asistencias', data)
};

export const metricasService = {
  getHistoricas: (params) => api.get('/metricas/historicas', { params }),
  getMensuales: (params) => api.get('/metricas/mensuales', { params }),
  calcular: (periodoId) => api.post(`/metricas/calcular/${periodoId}`),
  getTiempoReal: () => api.get('/metricas/tiempo-real')
};

export const analisisService = {
  getCrecimientoSemestral: () => api.get('/analisis/crecimiento-semestral'),
  getProyecciones: () => api.get('/analisis/proyecciones')
};

