const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Encryption key generation (same as frontend)
function generateKey() {
  const encoded = "" + Buffer.from("VEVSQQ==", 'base64').toString() + 
                  Buffer.from("QEJBQVAt", 'base64').toString() + 
                  "hu$BSDMK" + 
                  Buffer.from("QDU1NQ==", 'base64').toString();
  
  let key = "";
  for (let i = 0; i < encoded.length; i++) {
    key += String.fromCharCode(0 ^ encoded.charCodeAt(i));
  }
  return key;
}

// Decrypt function
async function decryptData(encryptedData, iv) {
  try {
    const key = generateKey();
    const keyBuffer = Buffer.from(key.slice(0, 32));
    
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      keyBuffer,
      Buffer.from(iv, 'base64')
    );
    
    const encryptedBuffer = Buffer.from(encryptedData, 'base64');
    const authTag = encryptedBuffer.slice(-16);
    const ciphertext = encryptedBuffer.slice(0, -16);
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return JSON.parse(decrypted.toString('utf8'));
  } catch (error) {
    throw new Error('Decryption failed: ' + error.message);
  }
}

// Encrypt function
async function encryptData(data) {
  try {
    const key = generateKey();
    const keyBuffer = Buffer.from(key.slice(0, 32));
    const iv = crypto.randomBytes(12);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    
    const plaintext = JSON.stringify(data);
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([encrypted, authTag]);
    
    return {
      data: combined.toString('base64'),
      iv: iv.toString('base64')
    };
  } catch (error) {
    throw new Error('Encryption failed: ' + error.message);
  }
}

// API Routes

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'active',
    message: 'Decryption API is running',
    endpoints: {
      decrypt: 'POST /api/decrypt',
      encrypt: 'POST /api/encrypt',
      health: 'GET /api/health'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Decrypt endpoint
app.post('/api/decrypt', async (req, res) => {
  try {
    const { data, iv } = req.body;
    
    if (!data || !iv) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: data and iv'
      });
    }
    
    const decrypted = await decryptData(data, iv);
    
    res.json({
      success: true,
      data: decrypted
    });
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Encrypt endpoint
app.post('/api/encrypt', async (req, res) => {
  try {
    const { data } = req.body;
    
    if (!data) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: data'
      });
    }
    
    const encrypted = await encryptData(data);
    
    res.json({
      success: true,
      ...encrypted
    });
  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Decryption API running on port ${PORT}`);
  console.log(`📍 Base URL: http://localhost:${PORT}`);
});

module.exports = app;
