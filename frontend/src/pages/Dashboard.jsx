import { useState, useEffect } from 'react';
import { dashboardService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { FaUserGraduate, FaMoneyBillWave, FaUsers, FaChalkboardTeacher, FaDoorOpen, FaPlus, FaUserPlus, FaCalendarAlt, FaBook, FaChartLine, FaRocket } from 'react-icons/fa';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import AlertasProrrogas from '../components/AlertasProrrogas';

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [tendencias, setTendencias] = useState([]);
  const [loading, setLoading] = useState(true);
  const isMaestro = user?.rol === 'maestro';

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const statsRes = await dashboardService.getStats();
      setStats(statsRes.data);

      // Intentar cargar tendencias, pero no fallar si no tiene permisos
      try {
        const tendenciasRes = await dashboardService.getTendencias();
        setTendencias(tendenciasRes.data);
      } catch (tendenciasError) {
        // Si es 403, el usuario no tiene permisos para ver tendencias
        if (tendenciasError.response?.status !== 403) {
          console.error('Error al cargar tendencias:', tendenciasError);
        }
      }
    } catch (error) {
      console.error('Error al cargar dashboard:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex justify-center items-center h-64">Cargando...</div>;
  }

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8', '#82CA9D'];
  const accionesRapidas = [
    {
      titulo: 'Agregar Alumno',
      descripcion: 'Registra un nuevo alumno en el sistema',
      icono: FaUserPlus,
      color: 'from-blue-500 to-blue-600',
      ruta: '/alumnos',
      accion: () => navigate('/alumnos'),
      rol: ['coordinador', 'administrativo']
    },
    {
      titulo: 'Registrar Pago',
      descripcion: 'Registra el pago de un alumno',
      icono: FaMoneyBillWave,
      color: 'from-green-500 to-green-600',
      ruta: '/pagos',
      accion: () => navigate('/pagos'),
      rol: ['coordinador', 'administrativo']
    },
    {
      titulo: 'Ver Mis Alumnos',
      descripcion: 'Consulta tu lista de alumnos',
      icono: FaUserGraduate,
      color: 'from-purple-500 to-purple-600',
      ruta: '/maestros-alumnos',
      accion: () => navigate('/maestros-alumnos'),
      rol: ['maestro']
    },
    {
      titulo: 'Crear Grupo',
      descripcion: 'Organiza un nuevo grupo de clases',
      icono: FaUsers,
      color: 'from-yellow-500 to-yellow-600',
      ruta: '/grupos',
      accion: () => navigate('/grupos'),
      rol: ['coordinador', 'administrativo']
    },
    {
      titulo: 'Gestionar Periodos',
      descripcion: 'Administra los periodos académicos',
      icono: FaCalendarAlt,
      color: 'from-pink-500 to-pink-600',
      ruta: '/periodos',
      accion: () => navigate('/periodos'),
      rol: ['coordinador']
    },
    {
      titulo: 'Tomar Asistencia',
      descripcion: 'Registra la asistencia de tus alumnos',
      icono: FaBook,
      color: 'from-indigo-500 to-indigo-600',
      ruta: '/asistencias',
      accion: () => navigate('/asistencias'),
      rol: ['maestro']
    },
    {
      titulo: 'Ver Reportes',
      descripcion: 'Consulta estadísticas y reportes',
      icono: FaChartLine,
      color: 'from-red-500 to-red-600',
      ruta: '/reportes',
      accion: () => navigate('/reportes'),
      rol: ['coordinador', 'administrativo']
    }
  ].filter(accion => accion.rol.includes(user?.rol));

  return (
    <div className="space-y-6">
      {/* Header con bienvenida personalizada */}
      <div className="card bg-gradient-to-r from-tescha-blue to-blue-700 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2">¡Hola, {user?.username}! 👋</h1>
            <p className="text-blue-100">
              {isMaestro
                ? 'Aquí puedes ver el resumen de tus grupos y alumnos'
                : 'Bienvenido al panel de control. Aquí tienes un resumen de todo el sistema'}
            </p>
          </div>
          <FaRocket className="text-6xl opacity-20" />
        </div>
      </div>

      {/* Acciones Rápidas - "¿Qué quieres hacer hoy?" */}
      {accionesRapidas.length > 0 && (
        <div className="card">
          <h2 className="text-xl font-bold text-gray-800 mb-4 flex items-center gap-2">
            <FaRocket className="text-tescha-blue" />
            ¿Qué quieres hacer hoy?
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {accionesRapidas.map((accion, index) => {
              const Icono = accion.icono;
              return (
                <button
                  key={index}
                  onClick={accion.accion}
                  className={`p-6 rounded-lg bg-gradient-to-br ${accion.color} text-white hover:shadow-lg transform hover:-translate-y-1 transition-all duration-200 text-left group`}
                >
                  <Icono className="text-3xl mb-3 group-hover:scale-110 transition-transform" />
                  <h3 className="font-bold text-lg mb-1">{accion.titulo}</h3>
                  <p className="text-sm opacity-90">{accion.descripcion}</p>
                  <div className="mt-3 flex items-center text-sm font-medium">
                    Ir ahora <span className="ml-2 group-hover:ml-3 transition-all">→</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Alertas de Prórrogas */}
      {!isMaestro && <AlertasProrrogas />}

      {/* Tarjetas de estadísticas */}
      <div className={`grid grid-cols-1 md:grid-cols-2 gap-6 ${isMaestro ? 'lg:grid-cols-4' : 'lg:grid-cols-5'}`}>
        <div className="card bg-gradient-to-br from-blue-500 to-blue-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-80">Alumnos Activos</p>
              <p className="text-3xl font-bold mt-2">{stats?.alumnos?.total || 0}</p>
              <p className="text-xs mt-1">Internos: {stats?.alumnos?.internos || 0} | Externos: {stats?.alumnos?.externos || 0}</p>
            </div>
            <FaUserGraduate className="text-4xl opacity-80" />
          </div>
        </div>

        {!isMaestro && (
          <div className="card bg-gradient-to-br from-green-500 to-green-600 text-white">
            <div className="flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <p className="text-sm opacity-80">Ingresos</p>
                <p className="text-2xl font-bold mt-2 break-words">${(stats?.pagos?.ingresos || 0).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
                <p className="text-xs mt-1 opacity-90">Por cobrar: ${(stats?.pagos?.por_cobrar || 0).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
              </div>
              <FaMoneyBillWave className="text-4xl opacity-80 flex-shrink-0 ml-3" />
            </div>
          </div>
        )}

        <div className="card bg-gradient-to-br from-purple-500 to-purple-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-80">Grupos Activos</p>
              <p className="text-3xl font-bold mt-2">{stats?.grupos_activos || 0}</p>
            </div>
            <FaUsers className="text-4xl opacity-80" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-yellow-500 to-yellow-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-80">Maestros</p>
              <p className="text-3xl font-bold mt-2">{stats?.maestros_activos || 0}</p>
            </div>
            <FaChalkboardTeacher className="text-4xl opacity-80" />
          </div>
        </div>

        <div className="card bg-gradient-to-br from-red-500 to-red-600 text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-80">Ocupación Salones</p>
              <p className="text-3xl font-bold mt-2">{stats?.salones?.tasa_ocupacion?.toFixed(0) || 0}%</p>
              <p className="text-xs mt-1">En uso: {stats?.salones?.en_uso || 0} / {(stats?.salones?.en_uso || 0) + (stats?.salones?.disponibles || 0)}</p>
            </div>
            <FaDoorOpen className="text-4xl opacity-80" />
          </div>
        </div>
      </div>

      {/* Gráficas */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alumnos por nivel */}
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Alumnos por Nivel</h3>
          <ResponsiveContainer width="100%" height={350}>
            <BarChart
              data={stats?.alumnos?.por_nivel || []}
              margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis
                dataKey="nivel_actual"
                tick={{ fontSize: 13, fontWeight: 500 }}
                stroke="#6b7280"
              />
              <YAxis
                tick={{ fontSize: 12 }}
                allowDecimals={false}
                stroke="#6b7280"
                tickFormatter={(value) => {
                  if (value >= 1000) return `${(value / 1000).toFixed(1)}K`;
                  return value;
                }}
              />
              <Tooltip
                contentStyle={{
                  fontSize: '14px',
                  backgroundColor: '#fff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                  boxShadow: '0 4px 6px rgba(0,0,0,0.1)'
                }}
                formatter={(value) => [
                  `${parseInt(value).toLocaleString('es-MX')} alumno${value !== 1 ? 's' : ''}`,
                  'Cantidad'
                ]}
                labelStyle={{ fontWeight: 600, marginBottom: '4px' }}
              />
              <Legend wrapperStyle={{ fontSize: '14px', paddingTop: '10px' }} />
              <Bar
                dataKey="cantidad"
                fill="#0369a1"
                name="Alumnos"
                radius={[8, 8, 0, 0]}
                maxBarSize={80}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Tendencias de ingresos - Solo para coordinadores y administrativos */}
        {!isMaestro && tendencias.length > 0 && (
          <div className="card">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                  <div className="p-2 bg-green-100 rounded-lg">
                    <FaChartLine className="text-green-600 text-lg" />
                  </div>
                  Tendencias de Ingresos
                </h3>
                <p className="text-sm text-gray-600 mt-1">Histórico de ingresos por periodo</p>
              </div>
              <div className="text-right bg-gradient-to-br from-green-50 to-emerald-50 p-4 rounded-xl border-2 border-green-200">
                <p className="text-xs font-semibold text-green-700 uppercase tracking-wide mb-1">Último Periodo</p>
                <p className="text-3xl font-bold text-green-600">
                  ${parseFloat(tendencias[tendencias.length - 1]?.ingresos || 0).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                </p>
                <p className="text-xs text-gray-600 mt-1">{tendencias[tendencias.length - 1]?.periodo}</p>
              </div>
            </div>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart
                data={tendencias}
                margin={{ top: 5, right: 30, left: 20, bottom: 50 }}
              >
                <defs>
                  <linearGradient id="colorIngresos" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" vertical={false} />
                <XAxis
                  dataKey="periodo"
                  tick={{ fontSize: 12, fill: '#4b5563', fontWeight: 500 }}
                  angle={-35}
                  textAnchor="end"
                  height={70}
                  stroke="#9ca3af"
                />
                <YAxis
                  tick={{ fontSize: 13, fill: '#4b5563', fontWeight: 500 }}
                  stroke="#9ca3af"
                  width={80}
                  tickFormatter={(value) => {
                    if (value >= 1000000) return `$${(value / 1000000).toFixed(1)}M`;
                    if (value >= 1000) return `$${(value / 1000).toFixed(0)}K`;
                    return `$${value}`;
                  }}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '2px solid #10b981',
                    borderRadius: '16px',
                    boxShadow: '0 12px 30px rgba(16, 185, 129, 0.25)',
                    padding: '16px'
                  }}
                  labelStyle={{
                    fontWeight: 700,
                    color: '#047857',
                    marginBottom: '8px',
                    fontSize: '15px'
                  }}
                  formatter={(value) => [
                    `$${parseFloat(value).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
                    'Ingresos'
                  ]}
                  itemStyle={{ color: '#059669', fontWeight: 600, fontSize: '14px' }}
                />
                <Line
                  type="monotone"
                  dataKey="ingresos"
                  stroke="#10b981"
                  strokeWidth={4}
                  dot={{
                    r: 6,
                    fill: '#10b981',
                    strokeWidth: 3,
                    stroke: '#fff'
                  }}
                  activeDot={{
                    r: 8,
                    fill: '#059669',
                    stroke: '#fff',
                    strokeWidth: 4
                  }}
                  fill="url(#colorIngresos)"
                />
              </LineChart>
            </ResponsiveContainer>
            <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center p-4 bg-gradient-to-br from-blue-50 to-blue-100 rounded-xl border border-blue-200">
                <div className="text-blue-600 font-bold text-sm uppercase tracking-wide mb-2">Periodos</div>
                <div className="text-3xl font-bold text-blue-700">{tendencias.length}</div>
                <div className="text-xs text-blue-600 mt-1">registrados</div>
              </div>
              <div className="text-center p-4 bg-gradient-to-br from-green-50 to-green-100 rounded-xl border border-green-200">
                <div className="text-green-600 font-bold text-sm uppercase tracking-wide mb-2">Total Acumulado</div>
                <div className="text-2xl font-bold text-green-700 break-words">
                  ${(tendencias.reduce((sum, t) => sum + parseFloat(t.ingresos || 0), 0)).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}
                </div>
                <div className="text-xs text-green-600 mt-1">pesos mexicanos</div>
              </div>
              <div className="text-center p-4 bg-gradient-to-br from-purple-50 to-purple-100 rounded-xl border border-purple-200">
                <div className="text-purple-600 font-bold text-sm uppercase tracking-wide mb-2">Promedio</div>
                <div className="text-2xl font-bold text-purple-700 break-words">
                  {tendencias.length > 0
                    ? `$${((tendencias.reduce((sum, t) => sum + parseFloat(t.ingresos || 0), 0) / tendencias.length)).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
                    : '$0.00'}
                </div>
                <div className="text-xs text-purple-600 mt-1">por periodo</div>
              </div>
            </div>
          </div>
        )}
      </div>


      {/* Alertas de Prórrogas Críticas - Solo para coordinadores */}
      {!isMaestro && stats?.alertas_prorrogas && (
        <div className="card bg-red-50 border-l-4 border-red-500">
          <div className="flex items-start space-x-3">
            <div className="text-red-500 text-2xl">⚠️</div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-red-800 mb-2">Alertas de Prórrogas - Periodo Actual</h3>
              <p className="text-sm text-gray-600 mb-4">Alumnos con prórroga que necesitan realizar su pago</p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="bg-white p-4 rounded-lg border-2 border-red-300 shadow-sm">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-3xl font-bold text-red-600">{stats.alertas_prorrogas.vencidas || 0}</p>
                    <span className="text-2xl">🚨</span>
                  </div>
                  <p className="text-sm font-semibold text-gray-700">Prórrogas Vencidas</p>
                  <p className="text-xs text-red-700 mt-1 font-medium">⚠️ Atención inmediata - Ya pasó la fecha límite</p>
                </div>
                <div className="bg-white p-4 rounded-lg border-2 border-orange-300 shadow-sm">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-3xl font-bold text-orange-600">{stats.alertas_prorrogas.por_vencer || 0}</p>
                    <span className="text-2xl">⏰</span>
                  </div>
                  <p className="text-sm font-semibold text-gray-700">Por Vencer (próximos 3 días)</p>
                  <p className="text-xs text-orange-700 mt-1 font-medium">📢 Notificar a los alumnos urgentemente</p>
                </div>
                <div className="bg-white p-4 rounded-lg border-2 border-yellow-300 shadow-sm">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-3xl font-bold text-yellow-600">{stats.alertas_prorrogas.activas || 0}</p>
                    <span className="text-2xl">📅</span>
                  </div>
                  <p className="text-sm font-semibold text-gray-700">Prórrogas Vigentes</p>
                  <p className="text-xs text-yellow-700 mt-1 font-medium">✅ Tienen tiempo - Deben pagar este periodo</p>
                </div>
              </div>

              {/* Lista expandible de alumnos urgentes */}
              {((stats.alertas_prorrogas.vencidas || 0) + (stats.alertas_prorrogas.por_vencer || 0)) > 0 && (
                <div className="mt-4 pt-4 border-t border-red-200">
                  <AlertasProrrogas compacto={true} mostrarSiempre={true} />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Estado de pagos - Solo para coordinadores y administrativos */}
      {!isMaestro && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Estado de Pagos del Período Actual</h3>
          <p className="text-sm text-gray-600 mb-4">Resumen financiero del periodo en curso</p>
          <div className="grid grid-cols-2 gap-6">
            <div className="text-center p-6 bg-gradient-to-br from-green-50 to-green-100 rounded-xl border-2 border-green-200 shadow-sm">
              <div className="flex items-center justify-center mb-3">
                <div className="p-3 bg-green-500 rounded-full">
                  <FaMoneyBillWave className="text-2xl text-white" />
                </div>
              </div>
              <p className="text-4xl font-bold text-green-600 mb-2">{stats?.pagos?.pagados || 0}</p>
              <p className="text-sm font-semibold text-gray-700 mb-1">Completados</p>
              <div className="mt-3 pt-3 border-t border-green-300">
                <p className="text-xs text-gray-600 mb-1">Ingresos del Mes</p>
                <p className="text-lg font-bold text-green-700">${(stats?.pagos?.ingresos || 0).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
              </div>
            </div>
            <div className="text-center p-6 bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-xl border-2 border-yellow-200 shadow-sm">
              <div className="flex items-center justify-center mb-3">
                <div className="p-3 bg-yellow-500 rounded-full">
                  <FaMoneyBillWave className="text-2xl text-white" />
                </div>
              </div>
              <p className="text-4xl font-bold text-yellow-600 mb-2">{stats?.pagos?.pendientes || 0}</p>
              <p className="text-sm font-semibold text-gray-700 mb-1">Pendientes con Prórroga</p>
              <div className="mt-3 pt-3 border-t border-yellow-300">
                <p className="text-xs text-gray-600 mb-1">Por Cobrar</p>
                <p className="text-lg font-bold text-yellow-700">${(stats?.pagos?.por_cobrar || 0).toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</p>
              </div>
            </div>
          </div>
          <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
            <p className="text-sm text-gray-700">
              <span className="font-semibold">💡 Nota:</span> Los pagos pendientes son aquellos alumnos que tienen prórroga activa para realizar su pago.
              Las prórrogas vencidas y por vencer se muestran en la sección de alertas arriba.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
