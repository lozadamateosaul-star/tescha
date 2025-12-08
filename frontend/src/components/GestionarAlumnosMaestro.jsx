import { useState, useEffect } from 'react';
import { maestrosAlumnosService } from '../services/api';
import { toast } from 'react-toastify';
import { FaUserPlus, FaTrash, FaTimes, FaUsers } from 'react-icons/fa';

const GestionarAlumnosMaestro = ({ maestro, onClose }) => {
  const [grupos, setGrupos] = useState([]);
  const [grupoSeleccionado, setGrupoSeleccionado] = useState(null);
  const [alumnosGrupo, setAlumnosGrupo] = useState([]);
  const [alumnosDisponibles, setAlumnosDisponibles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [buscador, setBuscador] = useState('');

  useEffect(() => {
    cargarGrupos();
  }, [maestro.id]);

  const cargarGrupos = async () => {
    try {
      const response = await maestrosAlumnosService.getGruposConAlumnos(maestro.id);
      setGrupos(response.data);
    } catch (error) {
      toast.error('Error al cargar grupos');
    } finally {
      setLoading(false);
    }
  };

  const seleccionarGrupo = async (grupo) => {
    setGrupoSeleccionado(grupo);
    setLoading(true);
    try {
      const [alumnosRes, disponiblesRes] = await Promise.all([
        maestrosAlumnosService.getAlumnosGrupo(maestro.id, grupo.id),
        maestrosAlumnosService.getAlumnosDisponibles(maestro.id, grupo.id)
      ]);
      setAlumnosGrupo(alumnosRes.data);
      setAlumnosDisponibles(disponiblesRes.data);
    } catch (error) {
      toast.error('Error al cargar alumnos');
    } finally {
      setLoading(false);
    }
  };

  const inscribirAlumno = async (alumnoId) => {
    try {
      await maestrosAlumnosService.inscribirAlumno(maestro.id, grupoSeleccionado.id, alumnoId);
      toast.success('¡Alumno inscrito exitosamente!');
      seleccionarGrupo(grupoSeleccionado); // Recargar
    } catch (error) {
      toast.error(error.response?.data?.error || 'Error al inscribir alumno');
    }
  };

  const removerAlumno = async (inscripcionId) => {
    if (!window.confirm('¿Seguro que deseas remover a este alumno del grupo?')) return;
    
    try {
      await maestrosAlumnosService.removerAlumno(maestro.id, grupoSeleccionado.id, inscripcionId);
      toast.success('Alumno removido del grupo');
      seleccionarGrupo(grupoSeleccionado); // Recargar
    } catch (error) {
      toast.error('Error al remover alumno');
    }
  };

  const alumnosFiltrados = alumnosDisponibles.filter(a =>
    a.nombre_completo.toLowerCase().includes(buscador.toLowerCase()) ||
    a.matricula.includes(buscador)
  );

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-4 flex justify-between items-center">
          <div>
            <h2 className="text-2xl font-bold">Gestionar Alumnos</h2>
            <p className="text-sm opacity-90">{maestro.nombre_completo}</p>
          </div>
          <button onClick={onClose} className="text-white hover:bg-white/20 p-2 rounded-lg transition">
            <FaTimes size={24} />
          </button>
        </div>

        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar: Lista de Grupos */}
          <div className="w-1/3 bg-gray-50 border-r overflow-y-auto">
            <div className="p-4">
              <h3 className="text-lg font-semibold mb-3 text-gray-700">Grupos del Maestro</h3>
              {loading && !grupoSeleccionado ? (
                <p className="text-gray-500 text-center py-8">Cargando grupos...</p>
              ) : grupos.length === 0 ? (
                <div className="text-center py-12 px-4">
                  <FaUsers size={64} className="mx-auto mb-4 text-gray-300" />
                  <h4 className="text-lg font-bold text-gray-700 mb-2">
                    ⚠️ Este maestro no tiene grupos
                  </h4>
                  <p className="text-sm text-gray-600 mb-4">
                    Primero debes crear grupos en la sección "Grupos" antes de poder inscribir alumnos.
                  </p>
                  <div className="bg-blue-50 border-2 border-blue-200 rounded-lg p-4 text-left mb-4">
                    <p className="text-sm font-semibold text-blue-900 mb-2">📋 Pasos a seguir:</p>
                    <ol className="text-xs text-blue-800 space-y-1 list-decimal list-inside">
                      <li>Ve a la página de <strong>"Grupos"</strong></li>
                      <li>Crea un grupo (ej: "A1-01")</li>
                      <li>Asigna este maestro al grupo</li>
                      <li>Regresa aquí para inscribir alumnos</li>
                    </ol>
                  </div>
                  <button
                    onClick={() => window.location.href = '/grupos'}
                    className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded-lg transition shadow-lg hover:shadow-xl"
                  >
                    🚀 Ir a Crear Grupos
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  {grupos.map(grupo => (
                    <button
                      key={grupo.id}
                      onClick={() => seleccionarGrupo(grupo)}
                      className={`w-full text-left p-4 rounded-lg border-2 transition ${
                        grupoSeleccionado?.id === grupo.id
                          ? 'bg-blue-100 border-blue-500 shadow-md'
                          : 'bg-white border-gray-200 hover:border-blue-300 hover:shadow'
                      }`}
                    >
                      <div className="font-bold text-gray-800">{grupo.codigo}</div>
                      <div className="text-sm text-gray-600">Nivel: {grupo.nivel}</div>
                      <div className="text-xs text-gray-500 mt-1">
                        👥 {grupo.total_alumnos} alumno{grupo.total_alumnos !== 1 ? 's' : ''}
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Panel Principal */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {!grupoSeleccionado ? (
              <div className="flex-1 flex items-center justify-center text-gray-400">
                <div className="text-center">
                  <FaUsers size={80} className="mx-auto mb-4 opacity-20" />
                  <p className="text-xl">Selecciona un grupo para gestionar sus alumnos</p>
                </div>
              </div>
            ) : (
              <>
                {/* Alumnos Inscritos */}
                <div className="p-4 border-b bg-white">
                  <h3 className="text-lg font-semibold text-gray-700 mb-2">
                    Alumnos Inscritos ({alumnosGrupo.length})
                  </h3>
                  <div className="max-h-40 overflow-y-auto">
                    {alumnosGrupo.length === 0 ? (
                      <p className="text-gray-400 text-sm py-2">No hay alumnos inscritos aún</p>
                    ) : (
                      <div className="space-y-1">
                        {alumnosGrupo.map(alumno => (
                          <div
                            key={alumno.id}
                            className="flex items-center justify-between p-2 bg-green-50 border border-green-200 rounded"
                          >
                            <div>
                              <span className="font-medium text-gray-800">{alumno.nombre_completo}</span>
                              <span className="text-xs text-gray-500 ml-2">({alumno.matricula})</span>
                            </div>
                            <button
                              onClick={() => removerAlumno(alumno.inscripcion_id)}
                              className="text-red-600 hover:text-red-800 hover:bg-red-100 p-1.5 rounded transition"
                              title="Remover del grupo"
                            >
                              <FaTrash size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Alumnos Disponibles */}
                <div className="flex-1 p-4 overflow-hidden flex flex-col">
                  <div className="mb-3">
                    <h3 className="text-lg font-semibold text-gray-700 mb-2">
                      Alumnos Disponibles para Inscribir ({alumnosFiltrados.length})
                    </h3>
                    <input
                      type="text"
                      placeholder="Buscar por nombre o matrícula..."
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      value={buscador}
                      onChange={(e) => setBuscador(e.target.value)}
                    />
                  </div>

                  <div className="flex-1 overflow-y-auto">
                    {loading ? (
                      <p className="text-gray-500 text-center py-8">Cargando alumnos...</p>
                    ) : alumnosFiltrados.length === 0 ? (
                      <div className="text-center py-8 text-gray-400">
                        <p>{buscador ? 'No se encontraron alumnos' : 'No hay alumnos disponibles del nivel ' + grupoSeleccionado.nivel}</p>
                      </div>
                    ) : (
                      <div className="space-y-2">
                        {alumnosFiltrados.map(alumno => (
                          <div
                            key={alumno.id}
                            className="flex items-center justify-between p-3 bg-gray-50 border border-gray-200 rounded-lg hover:border-blue-300 hover:shadow transition"
                          >
                            <div>
                              <div className="font-medium text-gray-800">{alumno.nombre_completo}</div>
                              <div className="text-xs text-gray-500">
                                {alumno.matricula} • {alumno.tipo_alumno} • Semestre {alumno.semestre}
                              </div>
                            </div>
                            <button
                              onClick={() => inscribirAlumno(alumno.id)}
                              className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 transition"
                            >
                              <FaUserPlus />
                              <span>Inscribir</span>
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default GestionarAlumnosMaestro;
