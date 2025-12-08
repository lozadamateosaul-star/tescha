import { useState, useEffect } from 'react';
import { salonesService } from '../services/api';
import { toast } from 'react-toastify';
import { FaPlus, FaEdit, FaTrash, FaDoorOpen } from 'react-icons/fa';
import { TooltipIcon } from '../components/Tooltip';

const Salones = () => {
  const [salones, setSalones] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editing, setEditing] = useState(null);
  const [formData, setFormData] = useState({ codigo: '', nombre: '', edificio: '', tipo: 'aula_tradicional', capacidad: 30, estatus: 'disponible' });

  useEffect(() => { loadSalones(); }, []);

  const loadSalones = async () => {
    try {
      const response = await salonesService.getAll();
      setSalones(response.data);
    } catch (error) {
      toast.error('Error al cargar salones');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = (salon = null) => {
    if (salon) {
      setEditing(salon);
      setFormData({ codigo: salon.codigo, nombre: salon.nombre, edificio: salon.edificio || '', tipo: salon.tipo, capacidad: salon.capacidad, estatus: salon.estatus });
    } else {
      setEditing(null);
      setFormData({ codigo: '', nombre: '', edificio: '', tipo: 'aula_tradicional', capacidad: 30, estatus: 'disponible' });
    }
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (editing) {
        await salonesService.update(editing.id, formData);
        toast.success('Salón actualizado');
      } else {
        await salonesService.create(formData);
        toast.success('Salón creado');
      }
      setShowModal(false);
      loadSalones();
    } catch (error) {
      toast.error('Error al guardar');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('¿Eliminar salón?')) return;
    try {
      await salonesService.delete(id);
      toast.success('Salón eliminado');
      loadSalones();
    } catch (error) {
      toast.error('Error al eliminar');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Gestión de Salones</h1>
        <button onClick={() => handleOpenModal()} className="btn-primary flex items-center space-x-2"><FaPlus /><span>Nuevo Salón</span></button>
      </div>

      <div className="card p-0">{loading ? <div className="p-8 text-center">Cargando...</div> : <table className="table"><thead><tr><th>Código</th><th>Nombre</th><th>Edificio</th><th>Tipo</th><th>Capacidad</th><th>Estatus</th><th>Acciones</th></tr></thead><tbody>{salones.map(s => (<tr key={s.id}><td className="font-medium">{s.codigo}</td><td>{s.nombre}</td><td>{s.edificio || 'N/A'}</td><td><span className="badge badge-info">{s.tipo}</span></td><td>{s.capacidad}</td><td><span className={`badge ${s.estatus === 'disponible' ? 'badge-success' : s.estatus === 'mantenimiento' ? 'badge-warning' : 'badge-danger'}`}>{s.estatus}</span></td><td><div className="flex space-x-2"><button onClick={() => handleOpenModal(s)} className="text-blue-600"><FaEdit /></button><button onClick={() => handleDelete(s.id)} className="text-red-600"><FaTrash /></button></div></td></tr>))}</tbody></table>}</div>

      {showModal && (<div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"><div className="bg-white rounded-lg max-w-2xl w-full p-6"><h2 className="text-2xl font-bold mb-4">{editing ? 'Editar' : 'Nuevo'} Salón</h2><div className="bg-blue-50 border-l-4 border-blue-500 p-3 mb-4"><div className="flex items-center"><span className="text-2xl mr-2">💡</span><p className="text-sm text-blue-900">Registra los salones disponibles para asignar a los grupos.</p></div></div><form onSubmit={handleSubmit} className="space-y-4"><div className="grid grid-cols-2 gap-4"><div><label className="flex items-center gap-2 text-sm font-medium mb-2">Código *<TooltipIcon text="Código identificador del salón (Ej: A-101)" /></label><input type="text" className="input" value={formData.codigo} onChange={(e) => setFormData({...formData, codigo: e.target.value})} required /></div><div><label className="block text-sm font-medium mb-2">Nombre *</label><input type="text" className="input" value={formData.nombre} onChange={(e) => setFormData({...formData, nombre: e.target.value})} required /></div></div><div className="grid grid-cols-2 gap-4"><div><label className="block text-sm font-medium mb-2">Edificio</label><input type="text" className="input" value={formData.edificio} onChange={(e) => setFormData({...formData, edificio: e.target.value})} /></div><div><label className="block text-sm font-medium mb-2">Tipo *</label><select className="input" value={formData.tipo} onChange={(e) => setFormData({...formData, tipo: e.target.value})} required><option value="aula_tradicional">Aula Tradicional</option><option value="laboratorio">Laboratorio</option><option value="sala_multimedia">Sala Multimedia</option></select></div></div><div className="grid grid-cols-2 gap-4"><div><label className="block text-sm font-medium mb-2">Capacidad *</label><input type="number" className="input" value={formData.capacidad} onChange={(e) => setFormData({...formData, capacidad: parseInt(e.target.value)})} required min="1" /></div><div><label className="block text-sm font-medium mb-2">Estatus</label><select className="input" value={formData.estatus} onChange={(e) => setFormData({...formData, estatus: e.target.value})}><option value="disponible">Disponible</option><option value="mantenimiento">Mantenimiento</option><option value="fuera_servicio">Fuera de Servicio</option></select></div></div><div className="flex justify-end space-x-3 mt-6"><button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancelar</button><button type="submit" className="btn-primary" disabled={loading}>{loading ? 'Guardando...' : editing ? 'Actualizar' : 'Crear'}</button></div></form></div></div>)}
    </div>
  );
};

export default Salones;
