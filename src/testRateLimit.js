const axios = require('axios');

// URL de tu API de registro
const API_URL = 'http://localhost:3001/api/auth/register';

// Función para generar un correo único
const generateUniqueEmail = (index) => `testuser${index}@example.com`;

// Función para enviar múltiples solicitudes de registro
const testRateLimit = async (numRequests = 150) => {
  console.log(`Enviando ${numRequests} solicitudes de registro...`);

  for (let i = 0; i < numRequests; i++) {
    const testUser = {
      username: `testuser${i}`,
      email: generateUniqueEmail(i),
      password: 'TestPassword123!',
    };

    try {
      const response = await axios.post(API_URL, testUser);
      console.log(`✅ [${i + 1}] Registro exitoso:`, response.data);
    } catch (error) {
      console.error(`❌ [${i + 1}] Error en la solicitud:`, error.response?.data || error.message);
    }
  }
};

// Ejecutar la prueba con 150 solicitudes
testRateLimit();
