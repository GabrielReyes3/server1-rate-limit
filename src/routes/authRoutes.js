// authRoutes.js
const express = require('express');
const router = express.Router();

// Importar controlador de autenticación
const authController = require('../controllers/authController');
// Importar controlador de logs
const logsController = require('../controllers/logsController');

// Importar configuración de Firebase (si es necesario)
const { db } = require('../config/firebase'); // ✅ Importa `db` desde `firebase.js`

// Definir la ruta GET /getInfo
router.get('/getInfo', (req, res) => {
  // Información hardcoded del alumno
  const alumno = {
    nombreCompleto: 'Gabriel Reyes',
    grupo: 'IDGS11'
  };

  // Información de la versión de Node.js
  const info = {
    versionNode: process.version,
    alumno: alumno
  };

  // Enviar la respuesta en formato JSON
  res.json(info);
});

// Rutas para logs
router.get('/logs', logsController.getLogs);  // Ruta para obtener los logs

// Rutas de autenticación
router.post('/register', authController.register);
router.post('/login', authController.login);

module.exports = router;
