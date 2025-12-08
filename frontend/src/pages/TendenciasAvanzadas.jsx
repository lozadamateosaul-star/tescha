import { useState, useEffect } from 'react';
import {
    LineChart, Line, BarChart, Bar, AreaChart, Area,
    XAxis, YAxis, CartesianGrid, Tooltip, Legend,
    ResponsiveContainer, ComposedChart
} from 'recharts';
import { FaChartLine, FaDownload, FaSync, FaInfoCircle } from 'react-icons/fa';
import { toast } from 'react-toastify';
import { metricasService, analisisService, reportesService } from '../services/api';

const TendenciasAvanzadas = () => {
    const [metricasHistoricas, setMetricasHistoricas] = useState([]);
    const [crecimientoSemestral, setCrecimientoSemestral] = useState(null);
    const [proyecciones, setProyecciones] = useState(null);
    const [loading, setLoading] = useState(true);
    const [vistaActual, setVistaActual] = useState('tendencias'); // tendencias, crecimiento, proyecciones

    useEffect(() => {
        cargarDatos();
    }, []);

    const cargarDatos = async () => {
        setLoading(true);
        try {
            const [historicasRes, crecimientoRes, proyeccionesRes] = await Promise.all([
                metricasService.getHistoricas({ limite: 12 }),
                analisisService.getCrecimientoSemestral(),
                analisisService.getProyecciones()
            ]);

            setMetricasHistoricas(historicasRes.data.data || []);
            setCrecimientoSemestral(crecimientoRes.data);
            setProyecciones(proyeccionesRes.data.proyecciones);
        } catch (error) {
            console.error('Error al cargar datos:', error);
            toast.error('Error al cargar métricas históricas');
        } finally {
            setLoading(false);
        }
    };

    const descargarPDFTendencias = async () => {
        try {
            toast.info('Generando PDF con gráficas...');
            const response = await reportesService.exportar('tendencias-ingresos', { formato: 'pdf' });

            const blob = new Blob([response.data], { type: 'application/pdf' });
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = `tendencias_ingresos_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);

            toast.success('PDF generado exitosamente');
        } catch (error) {
            console.error('Error al generar PDF:', error);
            toast.error('Error al generar PDF');
        }
    };

    const formatCurrency = (value) => {
        return `$${parseFloat(value).toLocaleString('es-MX', { minimumFractionDigits: 0, maximumFractionDigits: 0 })}`;
    };

    const formatNumber = (value) => {
        return parseInt(value).toLocaleString('es-MX');
    };

    if (loading) {
        return (
            <div className="flex justify-center items-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-tescha-blue"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-bold text-gray-800 flex items-center gap-2">
                        <FaChartLine className="text-tescha-blue" />
                        Análisis de Tendencias Históricas
                    </h1>
                    <p className="text-gray-600 mt-2">
                        Visualización de crecimiento y proyecciones basadas en datos históricos
                    </p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={cargarDatos}
                        className="btn-secondary flex items-center gap-2"
                    >
                        <FaSync />
                        Actualizar
                    </button>
                    <button
                        onClick={descargarPDFTendencias}
                        className="btn-primary flex items-center gap-2"
                    >
                        <FaDownload />
                        Descargar PDF con Gráficas
                    </button>
                </div>
            </div>

            {/* Tabs de navegación */}
            <div className="card">
                <div className="flex border-b border-gray-200">
                    <button
                        onClick={() => setVistaActual('tendencias')}
                        className={`px-6 py-3 font-medium transition-colors ${vistaActual === 'tendencias'
                            ? 'border-b-2 border-tescha-blue text-tescha-blue'
                            : 'text-gray-600 hover:text-gray-800'
                            }`}
                    >
                        Tendencias Históricas
                    </button>
                    <button
                        onClick={() => setVistaActual('crecimiento')}
                        className={`px-6 py-3 font-medium transition-colors ${vistaActual === 'crecimiento'
                            ? 'border-b-2 border-tescha-blue text-tescha-blue'
                            : 'text-gray-600 hover:text-gray-800'
                            }`}
                    >
                        Crecimiento Semestral
                    </button>
                    <button
                        onClick={() => setVistaActual('proyecciones')}
                        className={`px-6 py-3 font-medium transition-colors ${vistaActual === 'proyecciones'
                            ? 'border-b-2 border-tescha-blue text-tescha-blue'
                            : 'text-gray-600 hover:text-gray-800'
                            }`}
                    >
                        Proyecciones
                    </button>
                </div>
            </div>

            {/* Vista de Tendencias Históricas */}
            {vistaActual === 'tendencias' && (
                <div className="space-y-6">
                    {/* Gráfica de Ingresos y Adeudos */}
                    <div className="card">
                        <h3 className="text-lg font-semibold mb-4">Evolución de Ingresos y Adeudos</h3>
                        <ResponsiveContainer width="100%" height={400}>
                            <ComposedChart data={metricasHistoricas}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                <XAxis
                                    dataKey="periodo"
                                    tick={{ fontSize: 12 }}
                                    angle={-45}
                                    textAnchor="end"
                                    height={80}
                                />
                                <YAxis
                                    yAxisId="left"
                                    tick={{ fontSize: 12 }}
                                    tickFormatter={formatCurrency}
                                />
                                <YAxis
                                    yAxisId="right"
                                    orientation="right"
                                    tick={{ fontSize: 12 }}
                                    tickFormatter={formatCurrency}
                                />
                                <Tooltip
                                    formatter={(value, name) => [formatCurrency(value), name]}
                                    contentStyle={{
                                        backgroundColor: '#fff',
                                        border: '1px solid #e5e7eb',
                                        borderRadius: '8px'
                                    }}
                                />
                                <Legend />
                                <Area
                                    yAxisId="left"
                                    type="monotone"
                                    dataKey="ingresos"
                                    fill="#10b981"
                                    fillOpacity={0.2}
                                    stroke="#10b981"
                                    strokeWidth={3}
                                    name="Ingresos Totales"
                                />
                                <Line
                                    yAxisId="right"
                                    type="monotone"
                                    dataKey="adeudos"
                                    stroke="#ef4444"
                                    strokeWidth={2}
                                    dot={{ r: 4 }}
                                    name="Adeudos Pendientes"
                                />
                            </ComposedChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Gráfica de Crecimiento de Alumnos */}
                    <div className="card">
                        <h3 className="text-lg font-semibold mb-4">Crecimiento de Matrícula</h3>
                        <ResponsiveContainer width="100%" height={400}>
                            <ComposedChart data={metricasHistoricas}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                <XAxis
                                    dataKey="periodo"
                                    tick={{ fontSize: 12 }}
                                    angle={-45}
                                    textAnchor="end"
                                    height={80}
                                />
                                <YAxis
                                    tick={{ fontSize: 12 }}
                                    tickFormatter={formatNumber}
                                />
                                <Tooltip
                                    formatter={(value, name) => [formatNumber(value), name]}
                                    contentStyle={{
                                        backgroundColor: '#fff',
                                        border: '1px solid #e5e7eb',
                                        borderRadius: '8px'
                                    }}
                                />
                                <Legend />
                                <Bar
                                    dataKey="total_alumnos"
                                    fill="#0369a1"
                                    name="Total Alumnos"
                                    radius={[8, 8, 0, 0]}
                                />
                                <Line
                                    type="monotone"
                                    dataKey="nuevos_ingresos"
                                    stroke="#f59e0b"
                                    strokeWidth={3}
                                    dot={{ r: 5, fill: '#f59e0b' }}
                                    name="Nuevos Ingresos"
                                />
                            </ComposedChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Distribución por Nivel */}
                    <div className="card">
                        <h3 className="text-lg font-semibold mb-4">Distribución por Nivel (Último Periodo)</h3>
                        <ResponsiveContainer width="100%" height={350}>
                            <BarChart
                                data={metricasHistoricas.length > 0 ? [
                                    { nivel: 'A1', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_a1 || 0 },
                                    { nivel: 'A2', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_a2 || 0 },
                                    { nivel: 'B1', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_b1 || 0 },
                                    { nivel: 'B2', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_b2 || 0 },
                                    { nivel: 'C1', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_c1 || 0 },
                                    { nivel: 'C2', cantidad: metricasHistoricas[metricasHistoricas.length - 1].alumnos_c2 || 0 }
                                ] : []}
                                layout="vertical"
                            >
                                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                <XAxis type="number" />
                                <YAxis dataKey="nivel" type="category" />
                                <Tooltip />
                                <Bar dataKey="cantidad" fill="#8b5cf6" name="Alumnos" radius={[0, 8, 8, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            )}

            {/* Vista de Crecimiento Semestral */}
            {vistaActual === 'crecimiento' && crecimientoSemestral && (
                <div className="space-y-6">
                    {/* Tarjetas de Promedios */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div className="card bg-gradient-to-br from-blue-500 to-blue-600 text-white">
                            <p className="text-sm opacity-80">Crecimiento Promedio de Alumnos</p>
                            <p className="text-4xl font-bold mt-2">
                                {crecimientoSemestral.promedios.crecimiento_alumnos_promedio}%
                            </p>
                            <p className="text-xs mt-1">Por semestre</p>
                        </div>
                        <div className="card bg-gradient-to-br from-green-500 to-green-600 text-white">
                            <p className="text-sm opacity-80">Crecimiento Promedio de Ingresos</p>
                            <p className="text-4xl font-bold mt-2">
                                {crecimientoSemestral.promedios.crecimiento_ingresos_promedio}%
                            </p>
                            <p className="text-xs mt-1">Por semestre</p>
                        </div>
                        <div className="card bg-gradient-to-br from-purple-500 to-purple-600 text-white">
                            <p className="text-sm opacity-80">Nuevos Ingresos Promedio</p>
                            <p className="text-4xl font-bold mt-2">
                                {crecimientoSemestral.promedios.nuevos_ingresos_promedio}
                            </p>
                            <p className="text-xs mt-1">Alumnos por semestre</p>
                        </div>
                    </div>

                    {/* Tabla de Crecimiento */}
                    <div className="card">
                        <h3 className="text-lg font-semibold mb-4">Análisis Detallado por Periodo</h3>
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Periodo</th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Total Alumnos</th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Nuevos Ingresos</th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Crecimiento %</th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Ingresos</th>
                                        <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase">Crecimiento Ingresos %</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {crecimientoSemestral.periodos.map((periodo, index) => (
                                        <tr key={index} className="hover:bg-gray-50">
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                                                {periodo.periodo}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">
                                                {formatNumber(periodo.total_alumnos)}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">
                                                {formatNumber(periodo.alumnos_nuevos_ingreso)}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right">
                                                <span className={`font-semibold ${parseFloat(periodo.crecimiento_alumnos_porcentaje) > 0
                                                    ? 'text-green-600'
                                                    : parseFloat(periodo.crecimiento_alumnos_porcentaje) < 0
                                                        ? 'text-red-600'
                                                        : 'text-gray-600'
                                                    }`}>
                                                    {periodo.crecimiento_alumnos_porcentaje > 0 ? '+' : ''}
                                                    {periodo.crecimiento_alumnos_porcentaje}%
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right text-gray-900">
                                                {formatCurrency(periodo.ingresos_totales)}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-right">
                                                <span className={`font-semibold ${parseFloat(periodo.crecimiento_ingresos_porcentaje) > 0
                                                    ? 'text-green-600'
                                                    : parseFloat(periodo.crecimiento_ingresos_porcentaje) < 0
                                                        ? 'text-red-600'
                                                        : 'text-gray-600'
                                                    }`}>
                                                    {periodo.crecimiento_ingresos_porcentaje > 0 ? '+' : ''}
                                                    {periodo.crecimiento_ingresos_porcentaje}%
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}

            {/* Vista de Proyecciones */}
            {vistaActual === 'proyecciones' && proyecciones && (
                <div className="space-y-6">
                    <div className="card bg-blue-50 border-l-4 border-blue-500">
                        <div className="flex items-start gap-3">
                            <FaInfoCircle className="text-2xl text-blue-500 mt-1" />
                            <div>
                                <h3 className="font-semibold text-gray-800 mb-2">Sobre las Proyecciones</h3>
                                <p className="text-sm text-gray-700">
                                    Las proyecciones se calculan basándose en el promedio y desviación estándar
                                    de los últimos 4 periodos académicos. Estas son estimaciones estadísticas
                                    y pueden variar según factores externos.
                                </p>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Proyección de Alumnos */}
                        <div className="card">
                            <h3 className="text-lg font-semibold mb-4">Proyección de Alumnos - Próximo Periodo</h3>
                            <div className="space-y-4">
                                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                                    <p className="text-sm text-gray-600">Escenario Optimista</p>
                                    <p className="text-3xl font-bold text-green-600">
                                        {formatNumber(proyecciones.proyeccion_optimista_alumnos)}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">alumnos totales</p>
                                </div>

                                <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                                    <p className="text-sm text-gray-600">Escenario Esperado</p>
                                    <p className="text-3xl font-bold text-blue-600">
                                        {formatNumber(proyecciones.alumnos_esperados_proximo_periodo)}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">
                                        ± {formatNumber(proyecciones.margen_error_alumnos)} alumnos
                                    </p>
                                </div>

                                <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
                                    <p className="text-sm text-gray-600">Escenario Conservador</p>
                                    <p className="text-3xl font-bold text-yellow-600">
                                        {formatNumber(proyecciones.proyeccion_conservadora_alumnos)}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">alumnos totales</p>
                                </div>
                            </div>
                        </div>

                        {/* Proyección de Ingresos */}
                        <div className="card">
                            <h3 className="text-lg font-semibold mb-4">Proyección de Ingresos - Próximo Periodo</h3>
                            <div className="space-y-4">
                                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                                    <p className="text-sm text-gray-600">Ingresos Esperados</p>
                                    <p className="text-3xl font-bold text-green-600">
                                        {formatCurrency(proyecciones.ingresos_esperados)}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">
                                        ± {formatCurrency(proyecciones.margen_error_ingresos)}
                                    </p>
                                </div>

                                <div className="bg-purple-50 p-4 rounded-lg border border-purple-200">
                                    <p className="text-sm text-gray-600">Nuevos Ingresos Esperados</p>
                                    <p className="text-3xl font-bold text-purple-600">
                                        {formatNumber(proyecciones.nuevos_ingresos_esperados)}
                                    </p>
                                    <p className="text-xs text-gray-500 mt-1">alumnos nuevos</p>
                                </div>

                                <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
                                    <p className="text-sm text-gray-600 mb-2">Recomendaciones</p>
                                    <ul className="text-xs text-gray-700 space-y-1">
                                        <li>• Preparar infraestructura para {formatNumber(proyecciones.proyeccion_optimista_alumnos)} alumnos</li>
                                        <li>• Planificar contratación de maestros según demanda</li>
                                        <li>• Ajustar presupuesto basado en ingresos proyectados</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default TendenciasAvanzadas;
