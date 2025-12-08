import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { toast } from 'react-toastify';
import { FaEye, FaEyeSlash } from 'react-icons/fa';
import CambioPasswordModal from '../components/CambioPasswordModal';

const Login = () => {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [mostrarCambioPassword, setMostrarCambioPassword] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  // Redirigir si ya está autenticado, pero solo si no está esperando cambio de contraseña
  useEffect(() => {
    if (isAuthenticated && !mostrarCambioPassword) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, mostrarCambioPassword, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const result = await login(credentials);
      
      if (result.success) {
        // Verificar si requiere cambio de contraseña
        if (result.cambio_password_requerido) {
          // Guardamos el usuario temporalmente para pasarlo al modal
          setCredentials({ ...credentials, usuario: result.usuario });
          setMostrarCambioPassword(true);
          setLoading(false);
        } else {
          toast.success('¡Bienvenido!');
          setTimeout(() => {
            navigate('/', { replace: true });
          }, 500);
        }
      } else {
        toast.error(result.error || 'Contraseña incorrecta o usuario no encontrado');
        setLoading(false);
      }
    } catch (error) {
      toast.error('Contraseña incorrecta o usuario no encontrado');
      setLoading(false);
    }
  };

  const handlePasswordChanged = (usuario) => {
    // Ahora sí guardamos el usuario completo después del cambio de contraseña
    if (usuario) {
      localStorage.setItem('user', JSON.stringify(usuario));
    }
    setMostrarCambioPassword(false);
    toast.success('¡Bienvenido! Tu contraseña ha sido actualizada');
    setTimeout(() => {
      window.location.href = '/'; // Forzar recarga completa
    }, 500);
  };

  return (
    <>
      {mostrarCambioPassword && <CambioPasswordModal onSuccess={() => handlePasswordChanged(credentials.usuario)} />}
      
      <div className="min-h-screen bg-gradient-to-br from-tescha-blue to-blue-900 flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-white rounded-lg shadow-2xl p-8">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-tescha-blue mb-2">TESCHA</h1>
            <p className="text-gray-600">Sistema de Coordinación de Inglés</p>
            <div className="w-20 h-1 bg-tescha-gold mx-auto mt-4"></div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Usuario
              </label>
              <input
                type="text"
                value={credentials.username}
                onChange={(e) => setCredentials({ ...credentials, username: e.target.value })}
                className="input"
                placeholder="Ingrese su usuario"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Contraseña
              </label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={credentials.password}
                  onChange={(e) => setCredentials({ ...credentials, password: e.target.value })}
                  className="input pr-12"
                  placeholder="Ingrese su contraseña"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 focus:outline-none"
                  tabIndex={-1}
                >
                  {showPassword ? <FaEyeSlash size={20} /> : <FaEye size={20} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Iniciando sesión...' : 'Iniciar Sesión'}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-gray-600">
            <p>Tecnológico de Estudios Superiores de Chalco</p>
          </div>
        </div>
      </div>
    </>
  );
};

export default Login;
