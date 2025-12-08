import { useState, useEffect } from 'react';
import { maestrosService } from '../services/api';
import { toast } from 'react-toastify';
import { FaPlus, FaEdit, FaTrash, FaToggleOn, FaToggleOff, FaKey, FaUsers, FaCheckCircle, FaTimesCircle } from 'react-icons/fa';
import GestionarAlumnosMaestro from '../components/GestionarAlumnosMaestro';
import { Tooltip, TooltipIcon } from '../components/Tooltip';

const Maestros = () => {
  // Sistema de creación de credenciales automáticas
  const [maestros, setMaestros] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingMaestro, setEditingMaestro] = useState(null);
  const [credencialesCreadas, setCredencialesCreadas] = useState(null);
  const [passwordReseteada, setPasswordReseteada] = useState(null);
  const [filtroEstado, setFiltroEstado] = useState('todos'); // 'todos', 'activos', 'inactivos'
  const [formData, setFormData] = useState({ nombre: '', apellido_paterno: '', apellido_materno: '', correo: '', telefono: '', rfc: '', niveles: [] });
  const [validationState, setValidationState] = useState({});
  const nivelesDisponibles = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];
  const [maestroGestionAlumnos, setMaestroGestionAlumnos] = useState(null);

  const validateField = (name, value) => {
    switch(name) {
      case 'nombre':
      case 'apellido_paterno':
        return value.length >= 2;
      case 'correo':
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
      case 'telefono':
        return !value || /^\d{10}$/.test(value.replace(/\D/g, ''));
      case 'rfc':
        return !value || /^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/i.test(value);
      default:
        return true;
    }
  };

  const handleFieldChange = (name, value) => {
    setFormData({ ...formData, [name]: value });
    if (value) {
      setValidationState({ ...validationState, [name]: validateField(name, value) });
    } else {
      const newState = { ...validationState };
      delete newState[name];
      setValidationState(newState);
    }
  };

  useEffect(() => { loadMaestros(); }, []);

  const loadMaestros = async () => {
    try {
      const response = await maestrosService.getAll();
      setMaestros(response.data);
    } catch (error) {
      toast.error('Error al cargar maestros');
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = (maestro = null) => {
    if (maestro) {
      setEditingMaestro(maestro);
      setFormData({ nombre: maestro.nombre || '', apellido_paterno: maestro.apellido_paterno || '', apellido_materno: maestro.apellido_materno || '', correo: maestro.correo || '', telefono: maestro.telefono || '', rfc: maestro.rfc || '', niveles: maestro.niveles || [] });
    } else {
      setEditingMaestro(null);
      setFormData({ nombre: '', apellido_paterno: '', apellido_materno: '', correo: '', telefono: '', rfc: '', niveles: [] });
    }
    setCredencialesCreadas(null);
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (editingMaestro) {
        await maestrosService.update(editingMaestro.id, formData);
        toast.success('Maestro actualizado');
        setShowModal(false);
      } else {
        const response = await maestrosService.create(formData);
        toast.success('Maestro creado exitosamente');
        
        // Mostrar credenciales si se crearon
        if (response.data.usuario_creado) {
          setCredencialesCreadas(response.data.usuario_creado);
        } else {
          setShowModal(false);
        }
      }
      loadMaestros();
    } catch (error) {
      toast.error('Error al guardar');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('¿Está seguro de eliminar este maestro? Esta acción no se puede deshacer.')) return;
    try {
      await maestrosService.delete(id);
      toast.success('Maestro eliminado correctamente');
      loadMaestros();
    } catch (error) {
      const mensaje = error.response?.data?.error || 'Error al eliminar maestro';
      toast.error(mensaje, { autoClose: 5000 });
    }
  };

  const handleToggleStatus = async (maestro) => {
    const accion = maestro.activo ? 'desactivar' : 'activar';
    if (!window.confirm(`¿Desea ${accion} a ${maestro.nombre_completo}?`)) return;
    
    try {
      const response = await maestrosService.toggleStatus(maestro.id);
      toast.success(response.data.message);
      loadMaestros();
    } catch (error) {
      toast.error(`Error al ${accion} maestro`);
    }
  };

  const handleResetPassword = async (maestro) => {
    if (!window.confirm(`¿Restablecer contraseña de ${maestro.nombre_completo}?`)) return;
    
    try {
      const response = await maestrosService.resetPassword(maestro.id);
      toast.success('Contraseña restablecida');
      
      // Mostrar modal con nueva contraseña
      setPasswordReseteada({
        maestro: maestro.nombre_completo,
        password: response.data.nueva_password
      });
    } catch (error) {
      toast.error('Error al restablecer contraseña');
    }
  };

  const toggleNivel = (nivel) => {
    setFormData(prev => ({ ...prev, niveles: prev.niveles.includes(nivel) ? prev.niveles.filter(n => n !== nivel) : [...prev.niveles, nivel] }));
  };

  const maestrosFiltrados = maestros.filter(m => {
    if (filtroEstado === 'activos') return m.activo === true;
    if (filtroEstado === 'inactivos') return m.activo === false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Gestión de Maestros</h1>
        <button onClick={() => handleOpenModal()} className="btn-primary flex items-center space-x-2"><FaPlus /><span>Nuevo Maestro</span></button>
      </div>

      <div className="bg-white rounded-md shadow-sm border border-gray-200 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <span className="text-xs font-medium text-gray-500 uppercase">Filtrar:</span>
          <div className="flex gap-1.5">
            <button 
              onClick={() => setFiltroEstado('todos')} 
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                filtroEstado === 'todos' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              Todos <span className={`ml-1 ${filtroEstado === 'todos' ? 'opacity-80' : ''}`}>({maestros.length})</span>
            </button>
            <button 
              onClick={() => setFiltroEstado('activos')} 
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                filtroEstado === 'activos' 
                  ? 'bg-green-600 text-white' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              Activos <span className={`ml-1 ${filtroEstado === 'activos' ? 'opacity-80' : ''}`}>({maestros.filter(m => m.activo).length})</span>
            </button>
            <button 
              onClick={() => setFiltroEstado('inactivos')} 
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                filtroEstado === 'inactivos' 
                  ? 'bg-red-600 text-white' 
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              Inactivos <span className={`ml-1 ${filtroEstado === 'inactivos' ? 'opacity-80' : ''}`}>({maestros.filter(m => !m.activo).length})</span>
            </button>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-lg shadow-md border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center">
            <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            <p className="mt-4 text-gray-600 font-medium">Cargando maestros...</p>
          </div>
        ) : maestrosFiltrados.length === 0 ? (
          <div className="p-12 text-center">
            <p className="text-gray-500 text-lg font-medium">
              No se encontraron maestros {filtroEstado === 'activos' ? 'activos' : filtroEstado === 'inactivos' ? 'inactivos' : ''}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gradient-to-r from-blue-50 to-indigo-50 border-b-2 border-blue-200">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-48">Nombre Completo</th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-56">Correo Electrónico</th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-32">Teléfono</th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-36">RFC</th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider w-48">Niveles</th>
                  <th className="px-6 py-4 text-left text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-28">Estado</th>
                  <th className="px-6 py-4 text-center text-xs font-bold text-gray-700 uppercase tracking-wider whitespace-nowrap w-40">Acciones</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {maestrosFiltrados.map(m => (
                  <tr key={m.id} className={`transition-all duration-200 ${m.activo ? 'hover:bg-blue-50' : 'bg-gray-50 opacity-75 hover:bg-gray-100'}`}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-semibold text-gray-900">{m.nombre_completo}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-600">{m.correo}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-600">{m.telefono}</div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-600 font-mono">{m.rfc || '-'}</div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-2 min-w-[180px]">
                        {m.niveles?.map(n => (
                          <span key={n} className="px-3 py-1.5 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 border border-blue-200 whitespace-nowrap">
                            {n}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-3 py-1 inline-flex text-xs leading-5 font-bold rounded-full shadow-sm ${
                        m.activo 
                          ? 'bg-gradient-to-r from-green-100 to-green-200 text-green-800 border border-green-300' 
                          : 'bg-gradient-to-r from-red-100 to-red-200 text-red-800 border border-red-300'
                      }`}>
                        {m.activo ? '✓ Activo' : '✗ Inactivo'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex justify-center space-x-2">
                        <button 
                          onClick={() => setMaestroGestionAlumnos(m)} 
                          className="p-2.5 text-indigo-600 hover:text-indigo-800 hover:bg-indigo-100 rounded-lg transition-all duration-200 transform hover:scale-110" 
                          title="Gestionar Alumnos"
                        >
                          <FaUsers size={18} />
                        </button>
                        <button 
                          onClick={() => handleOpenModal(m)} 
                          className="p-2.5 text-blue-600 hover:text-blue-800 hover:bg-blue-100 rounded-lg transition-all duration-200 transform hover:scale-110" 
                          title="Editar Maestro"
                        >
                          <FaEdit size={18} />
                        </button>
                        <button 
                          onClick={() => handleToggleStatus(m)} 
                          className={`p-2.5 rounded-lg transition-all duration-200 transform hover:scale-110 ${
                            m.activo 
                              ? 'text-orange-600 hover:text-orange-800 hover:bg-orange-100' 
                              : 'text-green-600 hover:text-green-800 hover:bg-green-100'
                          }`}
                          title={m.activo ? 'Desactivar Maestro' : 'Activar Maestro'}
                        >
                          {m.activo ? <FaToggleOff size={18} /> : <FaToggleOn size={18} />}
                        </button>
                        <button 
                          onClick={() => handleResetPassword(m)} 
                          className="p-2.5 text-purple-600 hover:text-purple-800 hover:bg-purple-100 rounded-lg transition-all duration-200 transform hover:scale-110" 
                          title="Restablecer Contraseña"
                        >
                          <FaKey size={18} />
                        </button>
                        <button 
                          onClick={() => handleDelete(m.id)} 
                          className="p-2.5 text-red-600 hover:text-red-800 hover:bg-red-100 rounded-lg transition-all duration-200 transform hover:scale-110" 
                          title="Eliminar Maestro"
                        >
                          <FaTrash size={18} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {passwordReseteada && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-xl w-full p-6 shadow-2xl">
            <div className="text-center mb-4">
              <div className="bg-purple-100 rounded-full w-20 h-20 flex items-center justify-center mx-auto mb-3">
                <span className="text-5xl">🔑</span>
              </div>
              <h3 className="text-2xl font-bold text-purple-600">Contraseña Restablecida</h3>
              <p className="text-sm text-gray-600 mt-2">Nueva contraseña temporal para {passwordReseteada.maestro}</p>
            </div>
            
            <div className="bg-gradient-to-r from-red-50 to-pink-50 p-4 rounded-lg border-2 border-red-300 mb-4">
              <label className="text-sm font-semibold text-gray-700 mb-2 block">🔑 Nueva Contraseña Temporal:</label>
              <div className="flex items-center justify-between gap-2">
                <p className="text-xl font-mono font-bold text-red-700 break-all flex-1">{passwordReseteada.password}</p>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(passwordReseteada.password);
                    toast.success('¡Contraseña copiada!');
                  }}
                  className="text-sm bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition font-semibold whitespace-nowrap"
                >
                  📋 Copiar
                </button>
              </div>
            </div>
            
            <div className="bg-yellow-50 border-2 border-yellow-400 rounded-lg p-4 mb-4">
              <div className="flex gap-3">
                <span className="text-3xl">⚠️</span>
                <div className="flex-1">
                  <p className="text-sm font-bold text-yellow-900 mb-1">¡Importante!</p>
                  <p className="text-sm text-yellow-800 leading-relaxed">
                    Esta es una contraseña <strong>temporal</strong>. El maestro debe cambiarla en su primer acceso.
                    Copia y envía esta contraseña de forma segura.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="flex justify-end">
              <button 
                type="button" 
                onClick={() => setPasswordReseteada(null)} 
                className="btn-primary px-8 py-3 text-lg font-semibold"
              >
                ✓ Entendido
              </button>
            </div>
          </div>
        </div>
      )}

      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4" onClick={(e) => e.target === e.currentTarget && setShowModal(false)}>
          <div className="bg-white rounded-lg max-w-2xl w-full p-6 max-h-[90vh] overflow-y-auto shadow-2xl">
            <h2 className="text-2xl font-bold mb-4">{editingMaestro ? 'Editar' : 'Nuevo'} Maestro</h2>
            
            {credencialesCreadas ? (
              <div className="space-y-4">
                <div className="text-center mb-4">
                  <div className="bg-green-100 rounded-full w-20 h-20 flex items-center justify-center mx-auto mb-3">
                    <span className="text-5xl">🔐</span>
                  </div>
                  <h3 className="text-2xl font-bold text-green-600">¡Usuario Creado!</h3>
                  <p className="text-sm text-gray-600 mt-2">Se ha generado una contraseña temporal segura</p>
                </div>
                
                <div className="space-y-3">
                  <div className="bg-gradient-to-r from-blue-50 to-indigo-50 p-4 rounded-lg border-2 border-blue-200">
                    <label className="text-sm font-semibold text-gray-700 mb-2 block">👤 Usuario:</label>
                    <div className="flex items-center justify-between">
                      <p className="text-xl font-mono font-bold text-blue-900">{credencialesCreadas.username}</p>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(credencialesCreadas.username);
                          toast.success('Usuario copiado');
                        }}
                        className="text-xs bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded-full transition"
                      >
                        📋 Copiar
                      </button>
                    </div>
                  </div>
                  
                  <div className="bg-gradient-to-r from-red-50 to-pink-50 p-4 rounded-lg border-2 border-red-300">
                    <label className="text-sm font-semibold text-gray-700 mb-2 block">🔑 Contraseña Temporal:</label>
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-xl font-mono font-bold text-red-700 break-all flex-1">{credencialesCreadas.password_temporal}</p>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard.writeText(credencialesCreadas.password_temporal);
                          toast.success('¡Contraseña copiada!');
                        }}
                        className="text-sm bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition font-semibold whitespace-nowrap"
                      >
                        📋 Copiar
                      </button>
                    </div>
                  </div>
                  
                  <div className="bg-yellow-50 border-2 border-yellow-400 rounded-lg p-4">
                    <div className="flex gap-3">
                      <span className="text-3xl">⚠️</span>
                      <div className="flex-1">
                        <p className="text-sm font-bold text-yellow-900 mb-1">¡Importante!</p>
                        <p className="text-sm text-yellow-800 leading-relaxed">
                          Esta contraseña es <strong>temporal y segura</strong>. El maestro <strong>DEBE cambiarla</strong> en su primer acceso. 
                          Copia y envía estas credenciales de forma segura.
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="flex justify-end pt-4">
                  <button 
                    type="button" 
                    onClick={() => {
                      setShowModal(false);
                      setCredencialesCreadas(null);
                    }} 
                    className="btn-primary px-8 py-3 text-lg font-semibold"
                  >
                    ✓ Entendido
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="bg-blue-50 border-l-4 border-blue-500 p-3 mb-4">
                  <div className="flex items-center">
                    <span className="text-2xl mr-2">💡</span>
                    <p className="text-sm text-blue-900">
                      Los campos marcados con * son obligatorios. Verás un <span className="text-green-600 font-bold">✓</span> verde cuando un campo esté correcto.
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium mb-2">
                      Nombre *
                      <TooltipIcon text="Nombre del maestro (mínimo 2 caracteres)" />
                    </label>
                    <div className="relative">
                      <input type="text" className="input pr-10" value={formData.nombre} onChange={(e) => handleFieldChange('nombre', e.target.value)} required />
                      {validationState.nombre !== undefined && (
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                          {validationState.nombre ? <FaCheckCircle className="text-green-500" /> : <FaTimesCircle className="text-red-500" />}
                        </div>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium mb-2">
                      Apellido Paterno *
                      <TooltipIcon text="Apellido paterno del maestro" />
                    </label>
                    <div className="relative">
                      <input type="text" className="input pr-10" value={formData.apellido_paterno} onChange={(e) => handleFieldChange('apellido_paterno', e.target.value)} required />
                      {validationState.apellido_paterno !== undefined && (
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                          {validationState.apellido_paterno ? <FaCheckCircle className="text-green-500" /> : <FaTimesCircle className="text-red-500" />}
                        </div>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium mb-2">
                      Apellido Materno
                      <TooltipIcon text="Apellido materno del maestro (opcional)" />
                    </label>
                    <input type="text" className="input" value={formData.apellido_materno} onChange={(e) => setFormData({...formData, apellido_materno: e.target.value})} />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium mb-2">
                      Correo *
                      <TooltipIcon text="Correo electrónico institucional del maestro" />
                    </label>
                    <div className="relative">
                      <input type="email" className="input pr-10" value={formData.correo} onChange={(e) => handleFieldChange('correo', e.target.value)} required placeholder="ejemplo@tescha.edu.mx" />
                      {validationState.correo !== undefined && (
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                          {validationState.correo ? <FaCheckCircle className="text-green-500" /> : <FaTimesCircle className="text-red-500" />}
                        </div>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="flex items-center gap-2 text-sm font-medium mb-2">
                      Teléfono
                      <TooltipIcon text="Teléfono de contacto (10 dígitos)" />
                    </label>
                    <div className="relative">
                      <input type="tel" className="input pr-10" value={formData.telefono} onChange={(e) => handleFieldChange('telefono', e.target.value)} placeholder="5512345678" />
                      {validationState.telefono !== undefined && (
                        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                          {validationState.telefono ? <FaCheckCircle className="text-green-500" /> : <FaTimesCircle className="text-red-500" />}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-2">
                    RFC
                    <TooltipIcon text="RFC del maestro (13 caracteres)" />
                  </label>
                  <div className="relative">
                    <input type="text" className="input pr-10" value={formData.rfc} onChange={(e) => handleFieldChange('rfc', e.target.value.toUpperCase())} maxLength="13" placeholder="ABCD123456XYZ" />
                    {validationState.rfc !== undefined && (
                      <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
                        {validationState.rfc ? <FaCheckCircle className="text-green-500" /> : <FaTimesCircle className="text-red-500" />}
                      </div>
                    )}
                  </div>
                </div>
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-2">
                    Niveles que puede impartir
                    <TooltipIcon text="Selecciona los niveles de inglés que el maestro está capacitado para impartir" />
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {nivelesDisponibles.map(nivel => (
                      <label key={nivel} className="flex items-center space-x-2 cursor-pointer">
                        <input type="checkbox" checked={formData.niveles.includes(nivel)} onChange={() => toggleNivel(nivel)} className="rounded" />
                        <span>{nivel}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <div className="flex justify-end space-x-3 mt-6">
                  <button type="button" onClick={() => setShowModal(false)} className="btn-secondary">Cancelar</button>
                  <button type="submit" className="btn-primary" disabled={loading}>{loading ? 'Guardando...' : editingMaestro ? 'Actualizar' : 'Crear'}</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Modal de Gestión de Alumnos */}
      {maestroGestionAlumnos && (
        <GestionarAlumnosMaestro
          maestro={maestroGestionAlumnos}
          onClose={() => setMaestroGestionAlumnos(null)}
        />
      )}
    </div>
  );
};

export default Maestros;
