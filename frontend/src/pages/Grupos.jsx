import { useState, useEffect } from 'react';
import { gruposService, periodosService, maestrosService, salonesService } from '../services/api';
import { toast } from 'react-toastify';
import { FaPlus, FaEdit, FaTrash, FaUsers } from 'react-icons/fa';
import { useAuth } from '../context/AuthContext';
import { TooltipIcon } from '../components/Tooltip';

const Grupos = () => {
  const { user } = useAuth();
  const isMaestro = user?.rol === 'maestro';
  const [grupos, setGrupos] = useState([]);
  const [periodos, setPeriodos] = useState([]);
  const [maestros, setMaestros] = useState([]);
  const [salones, setSalones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [formData, setFormData] = useState({ codigo_grupo: '', nivel: 'A1', periodo_id: '', maestro_id: '', salon_id: '', horarios: '', cupo_maximo: 25 });

  useEffect(() => { loadData(); }, []);

  const loadData = async () => {
    try {
      const [gruposRes, periodosRes, maestrosRes, salonesRes] = await Promise.all([
        gruposService.getAll(),
        periodosService.getAll(),
        maestrosService.getAll(),
        salonesService.getAll()
      ]);
      setGrupos(gruposRes.data);
      setPeriodos(periodosRes.data.filter(p => p.activo));
      setMaestros(maestrosRes.data);
      setSalones(salonesRes.data.filter(s => s.estatus === 'disponible'));
    } catch (error) {
      toast.error('Error al cargar datos');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = (grupo = null) => {
    if (grupo) {
      setEditing(grupo);
      setFormData({ codigo_grupo: grupo.codigo_grupo, nivel: grupo.nivel, periodo_id: grupo.periodo_id, maestro_id: grupo.maestro_id, salon_id: grupo.salon_id, horarios: grupo.horarios || '', cupo_maximo: grupo.cupo_maximo });
    } else {
      setEditing(null);
      setFormData({ codigo_grupo: '', nivel: 'A1', periodo_id: periodos[0]?.id || '', maestro_id: '', salon_id: '', horarios: '', cupo_maximo: 25 });
    }
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (editing) {
        await gruposService.update(editing.id, formData);
        toast.success('Grupo actualizado');
      } else {
        await gruposService.create(formData);
        toast.success('Grupo creado');
      }
      setShowModal(false);
      loadData();
    } catch (error) {
      toast.error('Error al guardar');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('¿Eliminar grupo?')) return;
    try {
      await gruposService.delete(id);
      toast.success('Grupo eliminado');
      loadData();
    } catch (error) {
      toast.error('Error al eliminar');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">{isMaestro ? 'Mis Grupos' : 'Gestión de Grupos'}</h1>
        {!isMaestro && (
          <button onClick={() => handleOpenModal()} className="btn-primary flex items-center space-x-2"><FaPlus /><span>Nuevo Grupo</span></button>
        )}
      </div>

      <div className="card p-0">{loading ? <div className="p-8 text-center">Cargando...</div> : <table className="table"><thead><tr><th>Código</th><th>Nivel</th><th>Período</th><th>Maestro</th><th>Salón</th><th>Horarios</th><th>Cupo</th>{!isMaestro && <th>Acciones</th>}</tr></thead><tbody>{grupos.map(g => (<tr key={g.id}><td className="font-medium">{g.codigo_grupo}</td><td><span className="badge badge-primary">{g.nivel}</span></td><td>{g.periodo_nombre}</td><td>{g.maestro_nombre}</td><td>{g.salon_codigo}</td><td className="text-sm">{g.horarios || 'Sin horario'}</td><td>{g.alumnos_inscritos || 0}/{g.cupo_maximo}</td>{!isMaestro && <td><div className="flex space-x-2"><button onClick={() => handleOpenModal(g)} className="text-blue-600"><FaEdit /></button><button onClick={() => handleDelete(g.id)} className="text-red-600"><FaTrash /></button></div></td>}</tr>))}</tbody></table>}</div>

      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
            <h2 className="text-2xl font-bold mb-4">{editing ? 'Editar' : 'Nuevo'} Grupo</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="bg-blue-50 border-l-4 border-blue-500 p-3 mb-4">
                <div className="flex items-center">
                  <span className="text-2xl mr-2">💡</span>
                  <p className="text-sm text-blue-900">
                    Los campos marcados con * son obligatorios. Asigna un maestro y salón para cada grupo.
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-2">
                    Código *
                    <TooltipIcon text="Código único del grupo (Ej: A1-01)" />
                  </label>
                  <input type="text" className="input" value={formData.codigo_grupo} onChange={(e) => setFormData({...formData, codigo_grupo: e.target.value})} required placeholder="Ej: A1-01" />
                </div>
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-2">
                    Nivel *
                    <TooltipIcon text="Nivel de inglés del grupo según el Marco Común Europeo" />
                  </label>
                  <select className="input" value={formData.nivel} onChange={(e) => setFormData({...formData, nivel: e.target.value})} required>
                    <option value="A1">A1</option>
                    <option value="A2">A2</option>
                    <option value="B1">B1</option>
                    <option value="B2">B2</option>
                    <option value="C1">C1</option>
                    <option value="C2">C2</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-2">
                  Período *
                  <TooltipIcon text="Período escolar en el que se impartirá el grupo" />
                </label>
                <select className="input" value={formData.periodo_id} onChange={(e) => setFormData({...formData, periodo_id: e.target.value})} required>
                  <option value="">Seleccionar período</option>
                  {periodos.map(p => <option key={p.id} value={p.id}>{p.nombre}</option>)}
                </select>
              </div>
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-2">
                  Maestro *
                  <TooltipIcon text="Maestro que impartirá clases a este grupo" />
                </label>
                <select className="input" value={formData.maestro_id} onChange={(e) => setFormData({...formData, maestro_id: e.target.value})} required>
                  <option value="">Seleccionar maestro</option>
                  {maestros.map(m => <option key={m.id} value={m.id}>{m.nombre_completo}</option>)}
                </select>
              </div>
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-2">
                  Salón *
                  <TooltipIcon text="Salón donde se impartirán las clases" />
                </label>
                <select className="input" value={formData.salon_id} onChange={(e) => setFormData({...formData, salon_id: e.target.value})} required>
                  <option value="">Seleccionar salón</option>
                  {salones.map(s => <option key={s.id} value={s.id}>{s.codigo} - {s.nombre}</option>)}
                </select>
              </div>
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-2">
                  Horarios
                  <TooltipIcon text="Días y horario de clases (Ej: Lun-Mie 8:00-10:00)" />
                </label>
                <input type="text" className="input" value={formData.horarios} onChange={(e) => setFormData({...formData, horarios: e.target.value})} placeholder="Ej: Lun-Mie 8:00-10:00" />
              </div>
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-2">
                  Cupo Máximo *
                  <TooltipIcon text="Número máximo de alumnos que puede tener el grupo" />
                </label>
                <input type="number" className="input" value={formData.cupo_maximo} onChange={(e) => setFormData({...formData, cupo_maximo: parseInt(e.target.value)})} required min="1" />
              </div>
              <div className="flex justify-end space-x-3 mt-6">
                <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancelar</button>
                <button type="submit" className="btn-primary" disabled={loading}>{loading ? 'Guardando...' : editing ? 'Actualizar' : 'Crear'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Grupos;
