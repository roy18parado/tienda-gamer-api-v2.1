const express = require('express');
const db = require('../db');
const { requireRole } = require('../middleware/auth');
const router = express.Router();

// GET /productos (público) - CORREGIDO
router.get('/', async (req, res) => {
    try {
        // Query que obtiene la imagen MÁS RECIENTE y la nombra correctamente
        const result = await db.query(`
            SELECT
                p.id, p.nombre, p.descripcion, p.precio, p.stock, p.categoria_id,
                c.nombre AS categoria,
                -- Subconsulta para obtener la URL de la imagen más reciente
                (SELECT url
                 FROM imagenes_productos ip
                 WHERE ip.producto_id = p.id
                 ORDER BY ip.creado_en DESC -- Ordenar por fecha de creación DESCENDENTE
                 LIMIT 1                     -- Tomar solo la más reciente
                ) AS firstimageurl           -- Alias en MINÚSCULAS y sin comillas
            FROM productos p
            LEFT JOIN categorias c ON p.categoria_id = c.id
            ORDER BY p.creado_en DESC;     -- Ordenar productos por fecha de creación
        `);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener productos:', err); // Loguear error en el servidor
        res.status(500).json({ error: 'Error interno al obtener productos' });
    }
});

// POST /productos
router.post('/', requireRole('admin', 'super'), async (req, res) => {
  const { nombre, descripcion = null, precio = 0.0, stock = 0, categoria_id = null } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO productos (nombre, descripcion, precio, stock, categoria_id) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [nombre, descripcion, precio, stock, categoria_id]
    );
    res.status(201).json({
      id: result.rows[0].id,
      nombre, descripcion, precio, stock, categoria_id
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /productos/:id
router.put('/:id', requireRole('admin', 'super'), async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, precio, stock, categoria_id } = req.body;
  try {
    await db.query(
      'UPDATE productos SET nombre = $1, descripcion = $2, precio = $3, stock = $4, categoria_id = $5 WHERE id = $6',
      [nombre, descripcion, precio, stock, categoria_id, id]
    );
    res.json({ id, nombre, descripcion, precio, stock, categoria_id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /productos/:id
router.delete('/:id', requireRole('admin', 'super'), async (req, res) => {
  const { id } = req.params;
  try {
    await db.query('DELETE FROM productos WHERE id = $1', [id]);
    res.json({ mensaje: 'Producto eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
