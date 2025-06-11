import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import path from 'path';
import cookieParser from 'cookie-parser'
import { fileURLToPath } from 'url';
import db from './bd.js';
import dotenv from 'dotenv';


dotenv.config();



const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;



app.use(cookieParser());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'private')));



app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, './public', 'register.html'));
  });

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, './public', 'login.html'));
});


app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }

    const userExists = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
 
    const result = await db.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    

    res.redirect('/login');
  } catch (error) {
    console.error('Error al registrar usuario:', error);

    res.status(500).json({ error: 'Error interno del servidor' });
  }
});





app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    

    if (!email || !password) {
      return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    }
    

    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
  
    const user = result.rows[0];
    
    if (!user) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }
    

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }
    
    
    const token = jwt.sign(
      { email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1m' } 
    );
    
  
    const refreshToken = jwt.sign(
      { email: user.email },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' } 
    );
    

    await db.query(
      'INSERT INTO refresh_token (token, user_id) VALUES ($1, $2)',
      [refreshToken, user.id]
    );
    
    
    res.cookie('token', token, { 
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 60 * 60 * 1000, 
      path: '/'
    });
    
    res.cookie('refreshToken', refreshToken, { 
      httpOnly: true, 
      secure: true,
      sameSite: 'Strict',
      maxAge: 604800000, // 7 días
      path: '/' 
    });
    
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Error al iniciar sesión:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});


app.get('/logout',async (req, res) => {
  res.clearCookie('token');
  res.clearCookie('refreshToken');
  res.redirect('/login');
  await db.query(
    'DELETE FROM refresh_token WHERE token = $1',
    [req.cookies.refreshToken]
  );
});

async function requireAuth (req, res, next) {
  if (!req.cookies) {
    return res.status(401).redirect('/login');
  }

  const token = req.cookies.token; 
  const refreshToken = req.cookies.refreshToken; 
  
  if (!token) {
    return res.status(401).redirect('/login');
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("respuesta de decoded", decoded)

    

    console.log("Access Token válido");
    next();
  }catch (err) {
    console.log("Access Token no válido");
    if (err.name == 'TokenExpiredError') {
      console.log("Access Token Expirado");
      console.log("Reasginando token");
      

      if (!refreshToken) {
        console.log("Refresh token no encontrado: ", refreshToken);
        return res.status(401).redirect('/login');
      }

      const refreshTokenResult = await db.query( 'SELECT * FROM refresh_token WHERE token = $1', [refreshToken]);
      if (refreshTokenResult.rows.length === 0) {
        console.log("Refresh token no encontrado: ", refreshToken);
        return res.status(401).redirect('/login');
      }
      try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const newToken = jwt.sign(
          { email: decoded.email },
          process.env.JWT_SECRET,
          { expiresIn: '1m' }
        );
        console.log("Guardando cookie...")
        res.cookie('token', newToken, {
          httpOnly: false,
          secure: true,
          sameSite: 'Strict',
          maxAge:   60 * 60 * 1000,
          path: '/' 
        });
        return next();
      }catch (error) {
        console.error('Error al refrescar token:', error);
        res.status(403).json({ error: 'Token inválido o expirado' });
      }
    }
  }
}



  
  app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, './private', 'dashboard.html'));
  });



//Ejecutar servidor
const startServer = async () => {
    const connected = await db.testConnection();
    if (connected) {
        // Inicializar la base de datos 
        await db.initializeDatabase();
        
        // Iniciar el servidor
        app.listen(PORT, () => {
          console.log(`Servidor corriendo en http://localhost:${PORT}`);
        });
      } else {
        console.error('No se pudo iniciar el servidor debido a problemas con la base de datos');
      }
}

startServer();