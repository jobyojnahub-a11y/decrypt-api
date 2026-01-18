const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// The ACTUAL encryption key (from your frontend code)
const ENCRYPTION_KEY = "TERABBAP-hu$BSDMK@555";

// Decrypt function matching frontend logic
async function decryptData(encryptedData, iv) {
  try {
    // Convert key to 32-byte buffer for AES-256
    const keyBuffer = Buffer.alloc(32);
    keyBuffer.write(ENCRYPTION_KEY, 0, 'utf8');
    
    // Decode base64 inputs
    const encryptedBuffer = Buffer.from(encryptedData, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');
    
    // Extract auth tag (last 16 bytes) and ciphertext
    const authTag = encryptedBuffer.slice(-16);
    const ciphertext = encryptedBuffer.slice(0, -16);
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, ivBuffer);
    decipher.setAuthTag(authTag);
    
    // Decrypt
    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    // Parse JSON
    return JSON.parse(decrypted.toString('utf8'));
  } catch (error) {
    console.error('Decryption error details:', error.message);
    throw new Error('Decryption failed: ' + error.message);
  }
}

// Encrypt function matching frontend logic
async function encryptData(data) {
  try {
    // Convert key to 32-byte buffer for AES-256
    const keyBuffer = Buffer.alloc(32);
    keyBuffer.write(ENCRYPTION_KEY, 0, 'utf8');
    
    // Generate random 12-byte IV
    const iv = crypto.randomBytes(12);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    
    // Encrypt
    const plaintext = JSON.stringify(data);
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    // Combine encrypted data + auth tag
    const combined = Buffer.concat([encrypted, authTag]);
    
    return {
      data: combined.toString('base64'),
      iv: iv.toString('base64')
    };
  } catch (error) {
    console.error('Encryption error details:', error.message);
    throw new Error('Encryption failed: ' + error.message);
  }
}

// API Routes

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'active',
    message: 'Decryption API is running',
    version: '1.0.0',
    key: 'TERABBAP-hu$BSDMK@555',
    endpoints: {
      decrypt: 'POST /api/decrypt',
      encrypt: 'POST /api/encrypt',
      health: 'GET /api/health',
      test: 'GET /api/test'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    encryption: 'AES-256-GCM'
  });
});

// Test endpoint - encrypt sample data
app.get('/api/test', async (req, res) => {
  try {
    const testData = {
      success: true,
      message: 'This is a test message',
      timestamp: Date.now(),
      data: {
        user: 'test_user',
        value: 12345
      }
    };
    
    const encrypted = await encryptData(testData);
    const decrypted = await decryptData(encrypted.data, encrypted.iv);
    
    res.json({
      success: true,
      original: testData,
      encrypted: encrypted,
      decrypted: decrypted,
      match: JSON.stringify(testData) === JSON.stringify(decrypted)
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
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
    console.error('Decryption API error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      details: 'Make sure data and iv are valid base64 strings from encrypted response'
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
        error: 'Missing required field: data (object or value to encrypt)'
      });
    }
    
    const encrypted = await encryptData(data);
    
    res.json({
      success: true,
      ...encrypted,
      note: 'Use this encrypted data with the decrypt endpoint'
    });
  } catch (error) {
    console.error('Encryption API error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Batch decrypt endpoint (multiple encrypted items)
app.post('/api/decrypt/batch', async (req, res) => {
  try {
    const { items } = req.body;
    
    if (!items || !Array.isArray(items)) {
      return res.status(400).json({
        success: false,
        error: 'Missing required field: items (array of {data, iv} objects)'
      });
    }
    
    const results = await Promise.all(
      items.map(async (item, index) => {
        try {
          const decrypted = await decryptData(item.data, item.iv);
          return { success: true, index, data: decrypted };
        } catch (error) {
          return { success: false, index, error: error.message };
        }
      })
    );
    
    res.json({
      success: true,
      results,
      total: items.length,
      successful: results.filter(r => r.success).length
    });
  } catch (error) {
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
    error: 'Internal server error',
    message: err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    availableEndpoints: [
      'GET /',
      'GET /api/health',
      'GET /api/test',
      'POST /api/decrypt',
      'POST /api/encrypt',
      'POST /api/decrypt/batch'
    ]
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Decryption API running on port ${PORT}`);
  console.log(`📍 Base URL: http://localhost:${PORT}`);
  console.log(`🔑 Encryption Key: ${ENCRYPTION_KEY}`);
  console.log(`🔐 Algorithm: AES-256-GCM`);
  console.log(`\n✅ Test the API:`);
  console.log(`   curl http://localhost:${PORT}/api/test`);
});

module.exports = app;
