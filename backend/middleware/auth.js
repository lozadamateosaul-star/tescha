import jwt from 'jsonwebtoken';

export const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      throw new Error();
    }
    
    // 🔒 SEGURIDAD: Validación estricta de JWT
    // Solo permitir algoritmo HS256, prevenir 'none'
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256'], // Solo HS256, rechazar 'none' y otros
      complete: false
    });
    
    // Validar claims críticos
    if (!decoded.id || !decoded.username || !decoded.rol) {
      throw new Error('Token inválido: claims faltantes');
    }
    
    // Validar que el rol sea válido
    const rolesValidos = ['coordinador', 'maestro', 'administrativo', 'alumno'];
    if (!rolesValidos.includes(decoded.rol)) {
      throw new Error('Token inválido: rol no válido');
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Por favor autentícate' });
  }
};

export const checkRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.rol)) {
      return res.status(403).json({ error: 'No tienes permisos para realizar esta acción' });
    }
    next();
  };
};
