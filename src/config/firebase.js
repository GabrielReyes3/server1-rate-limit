const admin = require('firebase-admin');
require('doetenv').config();

let serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIAL);

// Inicialización solo una vez
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
}

const db = admin.firestore(); // ✅ Solo se declara aquí

module.exports = { admin, db };
