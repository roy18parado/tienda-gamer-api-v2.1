// db.js
require('dotenv').config();
const { Pool } = require('pg');

// Configura la conexión a Render PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Necesario para Render
});

// Método de consulta genérico
pool.query = (text, params) => {
  return pool.connect().then(client => {
    return client
      .query(text, params)
      .then(res => {
        client.release();
        return res;
      })
      .catch(err => {
        client.release();
        throw err;
      });
  });
};

module.exports = pool;
