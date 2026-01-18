const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Exact key generation from frontend code
function getEncryptionKey() {
  // From your frontend: atob("VEVSQQ==") + atob("QEJBQVAt") + "hu$BSDMK" + atob("QDU1NQ==")
  const part1 = Buffer.from("VEVSQQ==", 'base64').toString(); // "TELA"
  const part2 = Buffer.from("QEJBQVAt", 'base64').toString(); // "@BAAP-"
  const part3 = "hu$BSDMK";
  const part4 = Buffer.from("QDU1NQ==", 'base64').toString(); // "@555"
  
  const combined = part1 + part2 + part3 + part4;
  
  // XOR with 0 (from frontend)
  let key = "";
  for (let i = 0; i < combined.length; i++) {
    key += String.fromCharCode(0 ^ combined.charCodeAt(i));
  }
  
  return key;
}

const ENCRYPTION_KEY = getEncryptionKey();

// Decrypt function - EXACTLY matching frontend
async function decryptData(encryptedDataBase64, ivBase64) {
  try {
    // Get the key exactly as frontend does
    const keyString = getEncryptionKey();
    const keyBuffer = Buffer.alloc(32);
    const keyBytes = Buffer.from(keyString, 'utf8');
    keyBytes.copy(keyBuffer, 0, 0, Math.min(32, keyBytes.length));
    
    // Decode base64
    const encryptedBuffer = Buffer.from(encryptedDataBase64, 'base64');
    const ivBuffer = Buffer.from(ivBase64, 'base64');
    
    // Auth tag is last 16 bytes
    const authTagLength = 16;
    const authTag = encryptedBuffer.slice(-authTagLength);
    const ciphertext = encryptedBuffer.slice(0, -authTagLength);
    
    // Decrypt
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, ivBuffer);
    decipher.setAuthTag(authTag);
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]);
    
    // Parse JSON
    return JSON.parse(decrypted.toString('utf8'));
  } catch (error) {
    console.error('❌ Decryption failed:', error.message);
    throw error;
  }
}

// Encrypt function - matching frontend
async function encryptData(data) {
  try {
    const keyString = getEncryptionKey();
    const keyBuffer = Buffer.alloc(32);
    const keyBytes = Buffer.from(keyString, 'utf8');
    keyBytes.copy(keyBuffer, 0, 0, Math.min(32, keyBytes.length));
    
    const iv = crypto.randomBytes(12);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
    
    const plaintext = JSON.stringify(data);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, 'utf8'),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([encrypted, authTag]);
    
    return {
      data: combined.toString('base64'),
      iv: iv.toString('base64')
    };
  } catch (error) {
    console.error('❌ Encryption failed:', error.message);
    throw error;
  }
}

// Routes

app.get('/', (req, res) => {
  res.json({ 
    status: 'active',
    message: 'Decryption API is running',
    version: '1.0.1',
    algorithm: 'AES-256-GCM',
    endpoints: {
      decrypt: 'POST /api/decrypt',
      encrypt: 'POST /api/encrypt',
      health: 'GET /api/health',
      test: 'GET /api/test',
      debug: 'GET /api/debug',
      testSample: 'POST /api/decrypt/test'
    }
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    encryption: 'AES-256-GCM',
    keyLength: ENCRYPTION_KEY.length
  });
});

app.get('/api/debug', (req, res) => {
  const keyBuffer = Buffer.alloc(32);
  const keyBytes = Buffer.from(ENCRYPTION_KEY, 'utf8');
  keyBytes.copy(keyBuffer, 0, 0, Math.min(32, keyBytes.length));
  
  res.json({
    key_string: ENCRYPTION_KEY,
    key_length: ENCRYPTION_KEY.length,
    key_buffer_hex: keyBuffer.toString('hex').substring(0, 32) + '...',
    algorithm: 'AES-256-GCM',
    iv_length: 12,
    auth_tag_length: 16,
    note: 'Key is derived from base64 decoded parts + XOR operation'
  });
});

app.get('/api/test', async (req, res) => {
  try {
    const testData = {
      success: true,
      message: 'Test message',
      timestamp: Date.now()
    };
    
    const encrypted = await encryptData(testData);
    const decrypted = await decryptData(encrypted.data, encrypted.iv);
    
    res.json({
      success: true,
      test: 'PASSED',
      original: testData,
      encrypted: {
        data: encrypted.data.substring(0, 50) + '...',
        iv: encrypted.iv
      },
      decrypted: decrypted,
      match: JSON.stringify(testData) === JSON.stringify(decrypted)
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      test: 'FAILED',
      error: error.message
    });
  }
});

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
    console.error('Decrypt error:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Verify data and iv are valid base64 strings'
    });
  }
});

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
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

app.post('/api/decrypt/test', async (req, res) => {
  try {
    // Your exact sample data
    const sampleData = "coTQ9e8v4A9WBmxK9vn02Khkgsbov2KRfLrcW0R0I6H2Z//yKEyB+v5UbnIG2SPftrYdahROp/XeVDI5hwaQoJDbXaoTbJ1D3T/rxjpRkXyi3DHk7XRNy5nysGZRHAgKIHEpPep1qXi+NNAu+oEDbrlfbHM2eQgRNV5gUGj5U9MEIB9SSMsB5vgme5i6e9t/xCCxloRWPUvjVsTwiHMtNujof9tIw4gP/Gx4008km5/HnbfLKH8i1gcdyh9L+QB3uHCYLj+SMOqwFFt+fg44nnWDD0V+93j/kHWuSc9Fe1eTR1fEIzCjusJqGdSIi24jDlwex17jKlCD88lfYnXEtQCN870efIOVLVUgBCquMdmXvdDYCKkcqK7FhUDr4cuS+Y3qpm9WmM/pVQR86sob+yfJJmamz7l0Ox1UP9wSM4XJPvxI2R1z0aza7+viutCB5EXmf8B2cV1h25lIwpirOGkx6zF/nTWKHNmIIN42XX2O90T91Ra/QdPdOobLslmRJ2ahkqc2HE8B/nmwXaAJ5khRb63v01hiilvbFhUiU/8n/ob1jQhqNUOLsZxXjgBdFEASuonGMP1UZ6VtcgJn9FwVRZzKTjtRKJuYcYUesVkZYVILlTnZA/LzjxXt28nW8JxtRiOTc5oeGuF/U+ZUD0Xe/Zvns7EO";
    const sampleIv = "IjUTDj1TOYKxV9UI";
    
    const decrypted = await decryptData(sampleData, sampleIv);
    
    res.json({
      success: true,
      data: decrypted,
      message: '✅ Successfully decrypted your sample data!'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      hint: 'Key mismatch - server encryption key may differ from your data source'
    });
  }
});

app.post('/api/decrypt/batch', async (req, res) => {
  try {
    const { items } = req.body;
    
    if (!items || !Array.isArray(items)) {
      return res.status(400).json({
        success: false,
        error: 'Missing field: items (array of {data, iv})'
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

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error'
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Decryption API running on port ${PORT}`);
  console.log(`📍 URL: http://localhost:${PORT}`);
  console.log(`🔑 Key: ${ENCRYPTION_KEY}`);
  console.log(`\n✅ Test: curl http://localhost:${PORT}/api/test`);
  console.log(`✅ Sample: curl -X POST http://localhost:${PORT}/api/decrypt/test`);
});

module.exports = app;
