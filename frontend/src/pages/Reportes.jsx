import { useState } from 'react';
import { reportesService } from '../services/api';
import { toast } from 'react-toastify';
import { FaFileDownload, FaFileExcel, FaFilePdf, FaChartBar, FaChartLine, FaChartPie } from 'react-icons/fa';

const Reportes = () => {
  const [loading, setLoading] = useState(false);
  const [selectedPeriodo, setSelectedPeriodo] = useState('');

  const reportTypes = [
    {
      id: 'reprobacion',
      title: 'Índice de Reprobación',
      description: 'Alumnos que no han acreditado el nivel actual',
      icon: FaChartBar,
      color: 'red'
    },
    {
      id: 'desercion',
      title: 'Tasa de Deserción',
      description: 'Alumnos que abandonaron el curso',
      icon: FaChartLine,
      color: 'orange'
    },
    {
      id: 'ocupacion-salones',
      title: 'Ocupación de Salones',
      description: 'Uso de infraestructura por horario',
      icon: FaChartPie,
      color: 'blue'
    },
    {
      id: 'sin-requisito',
      title: 'Alumnos Sin Requisito',
      description: 'Alumnos externos sin documento requerido',
      icon: FaChartBar,
      color: 'purple'
    },
    {
      id: 'carga-maestros',
      title: 'Carga de Maestros',
      description: 'Grupos y horas asignadas por maestro',
      icon: FaChartLine,
      color: 'green'
    },
    {
      id: 'eficiencia-terminal',
      title: 'Eficiencia Terminal',
      description: 'Alumnos que completaron todos los niveles',
      icon: FaChartPie,
      color: 'teal'
    },
    {
      id: 'ingresos',
      title: 'Reporte de Ingresos',
      description: 'Análisis financiero de pagos y prórroga',
      icon: FaChartBar,
      color: 'yellow'
    },
    {
      id: 'prorrogas-activas',
      title: 'Prórrogas de Pago',
      description: 'Seguimiento de prórrogas activas y vencidas',
      icon: FaChartLine,
      color: 'orange'
    },
    {
      id: 'adeudos-criticos',
      title: 'Adeudos Críticos',
      description: 'Alumnos con pagos pendientes y vencidos',
      icon: FaChartBar,
      color: 'red'
    }
  ];

  const handleGenerateReport = async (reportId, format = 'excel') => {
    setLoading(true);
    try {
      const response = await reportesService.exportar(reportId, { formato: format });
      
      // Crear descarga del archivo binario
      const blob = new Blob([response.data], {
        type: format === 'excel' 
          ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
          : 'application/pdf'
      });
      
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `reporte_${reportId}_${new Date().toISOString().split('T')[0]}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast.success(`Reporte ${format === 'excel' ? 'Excel' : 'PDF'} generado exitosamente`);
    } catch (error) {
      console.error('Error al generar reporte:', error);
      toast.error('Error al generar reporte');
    } finally {
      setLoading(false);
    }
  };

  const getColorClasses = (color) => {
    const colors = {
      red: 'from-red-500 to-red-600',
      orange: 'from-orange-500 to-orange-600',
      blue: 'from-blue-500 to-blue-600',
      purple: 'from-purple-500 to-purple-600',
      green: 'from-green-500 to-green-600',
      teal: 'from-teal-500 to-teal-600',
      yellow: 'from-yellow-500 to-yellow-600'
    };
    return colors[color] || 'from-gray-500 to-gray-600';
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-800">Reportes y Estadísticas</h1>
          <p className="text-gray-600 mt-2">Genera reportes académicos y financieros del sistema</p>
        </div>
      </div>

      {/* Filtro de período */}
      <div className="card">
        <div className="flex items-center space-x-4">
          <label className="text-sm font-medium text-gray-700">
            Filtrar por período (opcional):
          </label>
          <select 
            className="input max-w-xs"
            value={selectedPeriodo}
            onChange={(e) => setSelectedPeriodo(e.target.value)}
          >
            <option value="">Todos los períodos</option>
            <option value="1">Enero-Junio 2024</option>
            <option value="2">Julio-Diciembre 2024</option>
          </select>
        </div>
      </div>

      {/* Grid de reportes */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {reportTypes.map((report) => {
          const Icon = report.icon;
          return (
            <div key={report.id} className="card hover:shadow-lg transition-shadow">
              <div className={`w-full h-2 bg-gradient-to-r ${getColorClasses(report.color)} rounded-t-lg -mt-6 -mx-6 mb-4`}></div>
              
              <div className="flex items-start space-x-4">
                <div className={`p-3 bg-gradient-to-r ${getColorClasses(report.color)} rounded-lg`}>
                  <Icon className="text-2xl text-white" />
                </div>
                
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-gray-800 mb-1">
                    {report.title}
                  </h3>
                  <p className="text-sm text-gray-600 mb-4">
                    {report.description}
                  </p>
                  
                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleGenerateReport(report.id, 'excel')}
                      disabled={loading}
                      className="flex-1 btn-secondary text-sm py-2 flex items-center justify-center space-x-1"
                    >
                      <FaFileExcel />
                      <span>Excel</span>
                    </button>
                    <button
                      onClick={() => handleGenerateReport(report.id, 'pdf')}
                      disabled={loading}
                      className="flex-1 btn-secondary text-sm py-2 flex items-center justify-center space-x-1"
                    >
                      <FaFilePdf />
                      <span>PDF</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Información adicional */}
      <div className="card bg-blue-50 border-l-4 border-tescha-blue">
        <div className="flex items-start space-x-3">
          <FaFileDownload className="text-2xl text-tescha-blue mt-1" />
          <div>
            <h3 className="font-semibold text-gray-800 mb-2">Información sobre los reportes</h3>
            <ul className="text-sm text-gray-700 space-y-1">
              <li>• Los reportes en Excel permiten análisis y filtrado de datos</li>
              <li>• Los reportes en PDF son ideales para impresión y presentación</li>
              <li>• Utiliza el filtro de período para reportes específicos</li>
              <li>• Los datos se actualizan en tiempo real desde la base de datos</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Reportes;
