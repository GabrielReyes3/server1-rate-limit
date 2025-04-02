const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const { admin } = require('../config/firebase'); // ✅ Importar desde firebase.js
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const express = require('express');
const app = express();


// Inicializar Firestore
const db = admin.firestore();
const usersCollection = db.collection('users');
const logsCollection = db.collection('logs');

// Ruta GET para obtener la información
app.get('/getInfo', (req, res) => {
    // Información hardcoding del Alumno
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

  

// 🔹 Registro de usuario
exports.register = async (req, res) => {
    // Validar errores de los datos enviados
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, username, password, grado, grupo } = req.body;

    // Verificar que todos los campos requeridos están presentes
    if (!email || !username || !password || !grado || !grupo) {
        return res.status(400).json({ msg: 'Todos los campos son requeridos' });
    }

    // Validar que grado y grupo sean cadenas de texto
    if (typeof grado !== 'string' || typeof grupo !== 'string') {
        return res.status(400).json({ msg: 'Grado y grupo deben ser cadenas de texto' });
    }

    const normalizedEmail = email.toLowerCase();

    try {
        // Verificar si el usuario ya existe
        const existingUser = await usersCollection.where('email', '==', normalizedEmail).get();
        if (!existingUser.empty) {
            return res.status(400).json({ msg: 'El usuario ya está registrado' });
        }

        // Hashear la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generar clave secreta para MFA
        const secret = speakeasy.generateSecret({ length: 20 });

        // Crear usuario en Firestore
        // Crear usuario en Firestore con el correo como ID
        await usersCollection.doc(normalizedEmail).set({
            email: normalizedEmail,
            username,
            password: hashedPassword,
            grado,
            grupo,
            mfaSecret: secret.base32,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        // Generar código QR para MFA
        const qrCode = await qrcode.toDataURL(secret.otpauth_url);

        // Responder con mensaje de éxito y el QR
        res.status(201).json({
            msg: 'Usuario registrado exitosamente',
            qrCode,
        });
    } catch (error) {
        res.status(500).json({ msg: 'Error en el servidor' });
    }
};

// 🔹 Login con JWT y MFA
exports.login = async (req, res) => {
    const { email, password, token, useMFA } = req.body; // 'useMFA' indica si se utilizará MFA

    if (!email || (!password && !useMFA)) {
        return res.status(400).json({ msg: 'Faltan datos en la solicitud' });
    }

    try {
        // Buscar usuario en Firestore
        const userSnapshot = await usersCollection.where('email', '==', email).get();
        if (userSnapshot.empty) {
            return res.status(400).json({ msg: 'Credenciales inválidas' });
        }

        const userDoc = userSnapshot.docs[0];
        const userData = userDoc.data();

        // Si no se usa MFA, se valida con la contraseña
        if (!useMFA) {
            const validPassword = await bcrypt.compare(password, userData.password);
            if (!validPassword) {
                return res.status(400).json({ msg: 'Credenciales inválidas' });
            }
        }

        // Verificar si el mfaSecret está presente, solo si se requiere MFA
        if (useMFA && !userData.mfaSecret) {
            return res.status(400).json({ msg: 'MFA no configurado' });
        }

        // Verificar el código MFA (OTP), solo si se requiere MFA
        if (useMFA) {
            const verified = speakeasy.totp.verify({
                secret: userData.mfaSecret,
                encoding: 'base32',
                token,
            });

            if (!verified) {
                return res.status(400).json({ msg: 'Código MFA inválido' });
            }
        }

        // Generar JWT
        const tokenJWT = jwt.sign({ email, username: userData.username }, process.env.JWT_SECRET, {
            expiresIn: '1h',
        });

        res.json({
            msg: 'Inicio de sesión exitoso',
            token: tokenJWT,
        });
    } catch (error) {
        console.error('Error al iniciar sesión:', error.message);
        res.status(500).json({
            msg: 'Error en el servidor',
            error: error.message,
        });
    }
};

