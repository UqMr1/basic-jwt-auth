const { Pool } = require('pg');
require('dotenv').config();


const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});


const testConnection = async () => {
  try {
    const client = await pool.connect();
    console.log('Conexión a la base de datos establecida correctamente');
    client.release();
    return true;
  } catch (error) {
    console.error('Error al conectar a la base de datos:', error);
    return false;
  }
};


async function initializeDatabase() {
  try {
 
    const usersTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'users'
      );
    `);
    
    if (!usersTableExists.rows[0].exists) {
      await pool.query(`
        CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          refresh_token TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);
      console.log('Tabla users creada correctamente');
    } else {
      const columnExists = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.columns 
          WHERE table_name = 'users' AND column_name = 'refresh_token'
        );
      `);
      
      if (!columnExists.rows[0].exists) {
        await pool.query(`
          ALTER TABLE users ADD COLUMN refresh_token TEXT;
        `);
        console.log('Columna refresh_token añadida correctamente');
      }
    }

    const refreshTokenTableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'refresh_token'
      );
    `);
    
    if (!refreshTokenTableExists.rows[0].exists) {
      await pool.query(`
        CREATE TABLE refresh_token (
          id SERIAL PRIMARY KEY,
          token TEXT NOT NULL,
          user_id INTEGER NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
      `);
      console.log('Tabla refresh_token creada correctamente');
    }
  } catch (error) {
    console.error('Error al inicializar la base de datos:', error);
    throw error;
  }
}

module.exports = {
  pool,
  testConnection,
  initializeDatabase,
  query: (text, params) => pool.query(text, params)
};