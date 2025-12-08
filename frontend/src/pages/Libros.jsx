import { useState, useEffect } from 'react';
import { librosService, alumnosService } from '../services/api';
import { toast } from 'react-toastify';
import { FaPlus, FaEdit, FaTrash, FaShoppingCart, FaBox, FaBook, FaMoneyBillWave, FaTimes } from 'react-icons/fa';
import { TooltipIcon } from '../components/Tooltip';

const NIVELES_INGLES = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'];

const Libros = () => {
  const [libros, setLibros] = useState([]);
  const [alumnos, setAlumnos] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [showVentaModal, setShowVentaModal] = useState(false);
  const [editingId, setEditingId] = useState(null);
  const [libroSeleccionado, setLibroSeleccionado] = useState(null);
  const [formData, setFormData] = useState({
    titulo: '',
    nivel: 'A1',
    precio: '',
    stock: '',
    editorial: '',
    isbn: ''
  });
  const [ventaData, setVentaData] = useState({
    alumno_id: '',
    cantidad: 1
  });

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [librosRes, alumnosRes] = await Promise.all([
        librosService.getAll(),
        alumnosService.getAll()
      ]);
      setLibros(Array.isArray(librosRes.data) ? librosRes.data : []);
      const alumnosArray = alumnosRes.data.alumnos || alumnosRes.data;
      setAlumnos(Array.isArray(alumnosArray) ? alumnosArray : []);
    } catch (error) {
      console.error('Error al cargar datos:', error);
      toast.error('Error al cargar datos');
      setLibros([]);
      setAlumnos([]);
    } finally {
      setLoading(false);
    }
  };

  const handleOpenModal = () => {
    setFormData({
      titulo: '',
      nivel: 'A1',
      precio: '',
      stock: '',
      editorial: '',
      isbn: ''
    });
    setEditingId(null);
    setShowModal(true);
  };

  const handleEdit = (libro) => {
    setFormData({
      titulo: libro.titulo,
      nivel: libro.nivel,
      precio: libro.precio,
      stock: libro.stock,
      editorial: libro.editorial || '',
      isbn: libro.isbn || ''
    });
    setEditingId(libro.id);
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      if (editingId) {
        await librosService.update(editingId, formData);
        toast.success('Libro actualizado correctamente');
      } else {
        await librosService.create(formData);
        toast.success('Libro registrado correctamente');
      }
      setShowModal(false);
      loadData();
    } catch (error) {
      console.error('Error:', error);
      toast.error(editingId ? 'Error al actualizar libro' : 'Error al registrar libro');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('¿Estás seguro de eliminar este libro?')) return;
    
    try {
      await librosService.delete(id);
      toast.success('Libro eliminado correctamente');
      loadData();
    } catch (error) {
      toast.error('Error al eliminar libro');
    }
  };

  const handleOpenVenta = (libro) => {
    setLibroSeleccionado(libro);
    setVentaData({
      alumno_id: '',
      cantidad: 1
    });
    setShowVentaModal(true);
  };

  const handleVenta = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await librosService.vender({
        alumno_id: ventaData.alumno_id,
        libro_id: libroSeleccionado.id,
        cantidad: parseInt(ventaData.cantidad),
        precio_venta: parseFloat(libroSeleccionado.precio)
      });
      toast.success('Venta registrada correctamente');
      setShowVentaModal(false);
      loadData();
    } catch (error) {
      console.error('Error:', error);
      toast.error(error.response?.data?.error || 'Error al registrar venta');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold text-gray-800">Gestión de Libros</h1>
        <button onClick={handleOpenModal} className="btn-primary flex items-center space-x-2">
          <FaPlus />
          <span>Nuevo Libro</span>
        </button>
      </div>

      {/* Estadísticas */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Total Libros</p>
              <p className="text-3xl font-bold text-tescha-blue">{libros.length}</p>
            </div>
            <FaBook className="text-4xl text-tescha-blue opacity-20" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">En Stock</p>
              <p className="text-3xl font-bold text-green-600">
                {libros.reduce((acc, libro) => acc + (libro.stock || 0), 0)}
              </p>
            </div>
            <FaBox className="text-4xl text-green-600 opacity-20" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Vendidos</p>
              <p className="text-3xl font-bold text-blue-600">0</p>
            </div>
            <FaShoppingCart className="text-4xl text-blue-600 opacity-20" />
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Ingresos</p>
              <p className="text-3xl font-bold text-tescha-gold">$0</p>
            </div>
            <FaMoneyBillWave className="text-4xl text-tescha-gold opacity-20" />
          </div>
        </div>
      </div>

      {/* Tabla */}
      <div className="card p-0 overflow-hidden">
        {loading ? (
          <div className="p-8 text-center">Cargando...</div>
        ) : libros.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  <th>ISBN</th>
                  <th>Título</th>
                  <th>Editorial</th>
                  <th>Nivel</th>
                  <th>Precio</th>
                  <th>Stock</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {libros.map((libro) => (
                  <tr key={libro.id} className="hover:bg-gray-50">
                    <td className="font-medium">{libro.isbn || 'N/A'}</td>
                    <td>{libro.titulo}</td>
                    <td>{libro.editorial || 'N/A'}</td>
                    <td>
                      <span className="badge badge-info">{libro.nivel}</span>
                    </td>
                    <td className="font-semibold">${parseFloat(libro.precio).toFixed(2)}</td>
                    <td>
                      <span className={`badge ${libro.stock > 10 ? 'badge-success' : libro.stock > 0 ? 'badge-warning' : 'badge-danger'}`}>
                        {libro.stock}
                      </span>
                    </td>
                    <td>
                      <div className="flex space-x-2">
                        <button 
                          onClick={() => handleEdit(libro)}
                          className="text-blue-600 hover:text-blue-800" 
                          title="Editar"
                        >
                          <FaEdit />
                        </button>
                        <button 
                          onClick={() => handleDelete(libro.id)}
                          className="text-red-600 hover:text-red-800" 
                          title="Eliminar"
                        >
                          <FaTrash />
                        </button>
                        <button 
                          onClick={() => handleOpenVenta(libro)}
                          className="text-green-600 hover:text-green-800" 
                          title="Vender"
                          disabled={libro.stock === 0}
                        >
                          <FaShoppingCart />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12">
            <FaBook className="mx-auto text-6xl text-gray-300 mb-4" />
            <p className="text-gray-500 mb-4">No hay libros registrados</p>
            <button onClick={handleOpenModal} className="btn-primary inline-flex items-center space-x-2">
              <FaPlus />
              <span>Agregar Primer Libro</span>
            </button>
          </div>
        )}
      </div>

      {/* Modal Agregar/Editar Libro */}
      {showModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-2xl w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-2xl font-bold">{editingId ? 'Editar Libro' : 'Nuevo Libro'}</h2>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-gray-600">
                <FaTimes size={24} />
              </button>
            </div>
            
            <div className="bg-blue-50 border-l-4 border-blue-500 p-3 mb-4">
              <div className="flex items-center">
                <span className="text-2xl mr-2">💡</span>
                <p className="text-sm text-blue-900">
                  Registra los libros de texto disponibles para venta a los alumnos.
                </p>
              </div>
            </div>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-1">
                  Título *
                  <TooltipIcon text="Nombre completo del libro de texto" />
                </label>
                <input
                  type="text"
                  className="input"
                  value={formData.titulo}
                  onChange={(e) => setFormData({...formData, titulo: e.target.value})}
                  required
                  placeholder="Ej: English File Elementary"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-1">
                    Nivel de Inglés *
                    <TooltipIcon text="Nivel del Marco Común Europeo para el que está diseñado el libro" />
                  </label>
                  <select
                    className="input"
                    value={formData.nivel}
                    onChange={(e) => setFormData({...formData, nivel: e.target.value})}
                    required
                  >
                    {NIVELES_INGLES.map(nivel => (
                      <option key={nivel} value={nivel}>{nivel}</option>
                    ))}
                  </select>
                  <p className="text-xs text-gray-500 mt-1">Marco Común Europeo</p>
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-1">
                    ISBN
                    <TooltipIcon text="Código internacional del libro (opcional)" />
                  </label>
                  <input
                    type="text"
                    className="input"
                    value={formData.isbn}
                    onChange={(e) => setFormData({...formData, isbn: e.target.value})}
                    placeholder="978-0-19-450000-0"
                  />
                </div>
              </div>

              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-1">
                  Editorial
                  <TooltipIcon text="Casa editorial que publicó el libro" />
                </label>
                <input
                  type="text"
                  className="input"
                  value={formData.editorial}
                  onChange={(e) => setFormData({...formData, editorial: e.target.value})}
                  placeholder="Ej: Oxford University Press"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-1">
                    Precio *
                    <TooltipIcon text="Precio de venta en pesos mexicanos" />
                  </label>
                  <input
                    type="number"
                    step="0.01"
                    min="0"
                    className="input"
                    value={formData.precio}
                    onChange={(e) => setFormData({...formData, precio: e.target.value})}
                    required
                    placeholder="0.00"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-2 text-sm font-medium mb-1">
                    Stock Inicial *
                    <TooltipIcon text="Cantidad de libros disponibles en inventario" />
                  </label>
                  <input
                    type="number"
                    min="0"
                    className="input"
                    value={formData.stock}
                    onChange={(e) => setFormData({...formData, stock: e.target.value})}
                    required
                    placeholder="0"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="btn-secondary"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Guardando...' : (editingId ? 'Actualizar' : 'Guardar')}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal Vender Libro */}
      {showVentaModal && libroSeleccionado && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg max-w-md w-full p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-2xl font-bold">Vender Libro</h2>
              <button onClick={() => setShowVentaModal(false)} className="text-gray-400 hover:text-gray-600">
                <FaTimes size={24} />
              </button>
            </div>
            
            <div className="mb-4 p-4 bg-blue-50 rounded-lg">
              <h3 className="font-semibold text-lg">{libroSeleccionado.titulo}</h3>
              <p className="text-sm text-gray-600">Nivel: {libroSeleccionado.nivel}</p>
              <p className="text-sm text-gray-600">Stock disponible: {libroSeleccionado.stock}</p>
              <p className="text-lg font-bold text-green-600 mt-2">Precio: ${parseFloat(libroSeleccionado.precio).toFixed(2)}</p>
            </div>

            <form onSubmit={handleVenta} className="space-y-4">
              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-1">
                  Alumno *
                  <TooltipIcon text="Alumno que compra el libro" />
                </label>
                <select
                  className="input"
                  value={ventaData.alumno_id}
                  onChange={(e) => setVentaData({...ventaData, alumno_id: e.target.value})}
                  required
                >
                  <option value="">Seleccionar alumno</option>
                  {alumnos.map(alumno => (
                    <option key={alumno.id} value={alumno.id}>
                      {alumno.nombre} {alumno.apellido_paterno} - {alumno.matricula}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="flex items-center gap-2 text-sm font-medium mb-1">
                  Cantidad *
                  <TooltipIcon text="Número de ejemplares a vender" />
                </label>
                <input
                  type="number"
                  min="1"
                  max={libroSeleccionado.stock}
                  className="input"
                  value={ventaData.cantidad}
                  onChange={(e) => setVentaData({...ventaData, cantidad: e.target.value})}
                  required
                />
              </div>

              <div className="p-3 bg-gray-50 rounded">
                <p className="text-sm text-gray-600">Total a pagar:</p>
                <p className="text-2xl font-bold text-green-600">
                  ${(parseFloat(libroSeleccionado.precio) * parseInt(ventaData.cantidad || 1)).toFixed(2)}
                </p>
              </div>

              <div className="flex justify-end space-x-3 pt-4">
                <button
                  type="button"
                  onClick={() => setShowVentaModal(false)}
                  className="btn-secondary"
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={loading}
                >
                  {loading ? 'Procesando...' : 'Registrar Venta'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Libros;
