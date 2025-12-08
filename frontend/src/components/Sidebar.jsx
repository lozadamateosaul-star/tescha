import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  FaHome, FaUserGraduate, FaChalkboardTeacher, FaUsers,
  FaDoorOpen, FaCalendar, FaMoneyBillWave, FaClipboardCheck,
  FaUserCheck, FaBook, FaChartBar, FaChartLine, FaUpload
} from 'react-icons/fa';

const Sidebar = () => {
  const location = useLocation();
  const { user, hasRole } = useAuth();

  const menuItems = [
    { path: '/', icon: FaHome, label: 'Dashboard', roles: ['coordinador', 'maestro', 'administrativo', 'alumno'] },
    { path: '/alumnos', icon: FaUserGraduate, label: 'Alumnos', roles: ['coordinador', 'administrativo', 'maestro'] },
    { path: '/maestros', icon: FaChalkboardTeacher, label: 'Maestros', roles: ['coordinador'] },
    { path: '/grupos', icon: FaUsers, label: 'Grupos', roles: ['coordinador', 'maestro'] },
    { path: '/salones', icon: FaDoorOpen, label: 'Salones', roles: ['coordinador'] },
    { path: '/periodos', icon: FaCalendar, label: 'Períodos', roles: ['coordinador'] },
    { path: '/pagos', icon: FaMoneyBillWave, label: 'Pagos', roles: ['coordinador', 'administrativo'] },
    { path: '/calificaciones', icon: FaClipboardCheck, label: 'Calificaciones', roles: ['coordinador'] },
    { path: '/maestro-calificaciones', icon: FaUpload, label: 'Subir Calificaciones', roles: ['maestro'] },
    { path: '/asistencias', icon: FaUserCheck, label: 'Asistencias', roles: ['coordinador'] },
    { path: '/maestro-asistencias', icon: FaUpload, label: 'Subir Asistencias', roles: ['maestro'] },
    { path: '/libros', icon: FaBook, label: 'Libros', roles: ['coordinador', 'administrativo'] },
    { path: '/reportes', icon: FaChartBar, label: 'Reportes', roles: ['coordinador'] },
    { path: '/tendencias', icon: FaChartLine, label: 'Tendencias', roles: ['coordinador', 'administrativo'] }
  ];

  const filteredMenuItems = menuItems.filter(item => hasRole(item.roles));

  return (
    <div className="bg-tescha-blue text-white w-64 flex-shrink-0 flex flex-col h-screen">
      <div className="p-6">
        <h1 className="text-2xl font-bold text-tescha-gold">TESCHA</h1>
        <p className="text-sm text-gray-300 mt-1">Coordinación de Inglés</p>
      </div>

      <nav className="flex-1 overflow-y-auto">
        {filteredMenuItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;

          return (
            <Link
              key={item.path}
              to={item.path}
              className={`flex items-center px-6 py-3 text-gray-300 hover:bg-blue-800 hover:text-white transition-colors ${isActive ? 'bg-blue-800 text-white border-l-4 border-tescha-gold' : ''
                }`}
            >
              <Icon className="w-5 h-5 mr-3" />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-6 bg-blue-900 border-t border-blue-800">
        <div className="flex items-center">
          <div className="w-10 h-10 rounded-full bg-tescha-gold flex items-center justify-center text-tescha-blue font-bold">
            {user?.username?.charAt(0).toUpperCase()}
          </div>
          <div className="ml-3">
            <p className="text-sm font-medium">{user?.username}</p>
            <p className="text-xs text-gray-300 capitalize">{user?.rol}</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
