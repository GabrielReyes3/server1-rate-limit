// Importar Firestore desde Firebase
const { admin } = require('../config/firebase'); // Asegúrate de tener configurada la conexión a Firebase
const db = admin.firestore();
const logsCollection = db.collection('logs');


// 🔹 Obtener logs
exports.getLogs = async (req, res) => {
    try {
        // Obtener todos los logs desde Firestore
        const snapshot = await logsCollection.orderBy('timestamp', 'desc').get();
        
        if (snapshot.empty) {
            return res.status(404).json({ msg: 'No hay logs disponibles' });
        }

        // Mapeamos los logs para devolver los datos relevantes
        const logs = snapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
        }));

        // Enviar los logs en la respuesta
        res.status(200).json(logs);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Error al obtener logs' });
    }
};
