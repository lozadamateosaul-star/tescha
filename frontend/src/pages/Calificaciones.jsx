import { useState, useEffect } from 'react';
import { calificacionesService, gruposService } from '../services/api';
import { toast } from 'react-toastify';
import { FaSave, FaChartLine } from 'react-icons/fa';

const Calificaciones = () => {
  const [grupos, setGrupos] = useState([]);
  const [selectedGrupo, setSelectedGrupo] = useState('');
  const [selectedParcial, setSelectedParcial] = useState('1');
  const [alumnos, setAlumnos] = useState([]);
  const [calificaciones, setCalificaciones] = useState({});
  const [loading, setLoading] = useState(false);

  useEffect(() => { loadGrupos(); }, []);

  const loadGrupos = async () => {
    try {
      const response = await gruposService.getAll();
      setGrupos(response.data);
    } catch (error) {
      toast.error('Error al cargar grupos');
    }
  };

  const loadCalificaciones = async () => {
    if (!selectedGrupo) return;
    setLoading(true);
    try {
      const response = await calificacionesService.getByGrupo(selectedGrupo, selectedParcial);
      const data = Array.isArray(response.data) ? response.data : [];
      setAlumnos(data);
      const cals = {};
      data.forEach(alumno => {
        const calificacionParcial = alumno.calificaciones?.find(c => c.parcial === parseInt(selectedParcial));
        cals[alumno.alumno_id] = { 
          inscripcion_id: alumno.inscripcion_id,
          calificacion: calificacionParcial?.calificacion || '', 
          observaciones: calificacionParcial?.observaciones || '' 
        };
      });
      setCalificaciones(cals);
    } catch (error) {
      console.error('Error al cargar calificaciones:', error);
      toast.error('Error al cargar calificaciones');
      setAlumnos([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadCalificaciones(); }, [selectedGrupo, selectedParcial]);

  const handleCalificacionChange = (alumnoId, field, value) => {
    setCalificaciones(prev => ({
      ...prev,
      [alumnoId]: { ...prev[alumnoId], [field]: value }
    }));
  };

  const handleSave = async () => {
    if (!selectedGrupo) return;
    setLoading(true);
    try {
      const data = alumnos.map(a => ({
        inscripcion_id: calificaciones[a.alumno_id]?.inscripcion_id,
        alumno_id: a.alumno_id,
        grupo_id: parseInt(selectedGrupo),
        parcial: parseInt(selectedParcial),
        calificacion: parseFloat(calificaciones[a.alumno_id]?.calificacion || 0),
        observaciones: calificaciones[a.alumno_id]?.observaciones || ''
      }));
      await calificacionesService.saveMultiple(data);
      toast.success('Calificaciones guardadas correctamente');
      loadCalificaciones();
    } catch (error) {
      console.error('Error al guardar:', error);
      toast.error('Error al guardar calificaciones');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Calificaciones</h1>
        <button onClick={handleSave} disabled={!selectedGrupo || loading} className="btn-primary flex items-center space-x-2"><FaSave /><span>Guardar Calificaciones</span></button>
      </div>

      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium mb-2">Seleccionar Grupo *</label>
            <select className="input" value={selectedGrupo} onChange={(e) => setSelectedGrupo(e.target.value)}>
              <option value="">-- Seleccionar grupo --</option>
              {grupos.map(g => <option key={g.id} value={g.id}>{g.codigo_grupo} - {g.nivel} ({g.maestro_nombre})</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Parcial *</label>
            <select className="input" value={selectedParcial} onChange={(e) => setSelectedParcial(e.target.value)}>
              <option value="1">Primer Parcial</option>
              <option value="2">Segundo Parcial</option>
              <option value="3">Tercer Parcial</option>
            </select>
          </div>
        </div>

        {selectedGrupo && (
          <div>
            {loading ? (
              <div className="text-center py-8">Cargando...</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Matrícula</th>
                      <th>Nombre</th>
                      <th>Calificación (0-100)</th>
                      <th>Observaciones</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alumnos.map(alumno => (
                      <tr key={alumno.alumno_id}>
                        <td className="font-medium">{alumno.matricula}</td>
                        <td>{alumno.nombre_completo}</td>
                        <td>
                          <input
                            type="number"
                            className="input w-24"
                            min="0"
                            max="100"
                            step="0.1"
                            value={calificaciones[alumno.alumno_id]?.calificacion || ''}
                            onChange={(e) => handleCalificacionChange(alumno.alumno_id, 'calificacion', e.target.value)}
                          />
                        </td>
                        <td>
                          <input
                            type="text"
                            className="input"
                            placeholder="Notas adicionales"
                            value={calificaciones[alumno.alumno_id]?.observaciones || ''}
                            onChange={(e) => handleCalificacionChange(alumno.alumno_id, 'observaciones', e.target.value)}
                          />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Calificaciones;
