// config/security.js
const crypto = require('crypto');

/**
 * Security configuration and utilities for the EcoChain application
 */

// Generate a secure encryption key if not provided in environment variables
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 
  crypto.randomBytes(32).toString('hex');

// Generate a secure initialization vector for encryption
const generateIV = () => crypto.randomBytes(16);

/**
 * Encrypt sensitive data
 * @param {string} text - Text to encrypt
 * @returns {Object} - Object containing encrypted text and IV
 */
const encrypt = (text) => {
  if (!text) return null;
  
  const iv = generateIV();
  const cipher = crypto.createCipheriv(
    'aes-256-cbc', 
    Buffer.from(ENCRYPTION_KEY, 'hex'), 
    iv
  );
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    iv: iv.toString('hex'),
    encryptedData: encrypted
  };
};

/**
 * Decrypt sensitive data
 * @param {Object} encryptedData - Object containing encrypted text and IV
 * @returns {string} - Decrypted text
 */
const decrypt = (encryptedData) => {
  if (!encryptedData || !encryptedData.iv || !encryptedData.encryptedData) {
    return null;
  }
  
  try {
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc', 
      Buffer.from(ENCRYPTION_KEY, 'hex'), 
      iv
    );
    
    let decrypted = decipher.update(encryptedData.encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

/**
 * Hash sensitive data (one-way)
 * @param {string} data - Data to hash
 * @returns {string} - Hashed data
 */
const hash = (data) => {
  if (!data) return null;
  return crypto.createHash('sha256').update(data).digest('hex');
};

/**
 * Generate a secure random token
 * @param {number} length - Length of token
 * @returns {string} - Random token
 */
const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Sanitize object by removing sensitive fields
 * @param {Object} obj - Object to sanitize
 * @param {Array} sensitiveFields - Fields to remove
 * @returns {Object} - Sanitized object
 */
const sanitizeObject = (obj, sensitiveFields = ['password', 'refreshToken', 'otp']) => {
  if (!obj) return null;
  
  const sanitized = { ...obj };
  sensitiveFields.forEach(field => {
    if (sanitized[field]) delete sanitized[field];
  });
  
  return sanitized;
};

/**
 * Rate limiting configuration
 */
const rateLimits = {
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 requests per windowMs
    message: { success: false, message: 'Too many login attempts, please try again later', code: 'RATE_LIMIT_EXCEEDED' }
  },
  api: {
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 requests per windowMs
    message: { success: false, message: 'Too many requests, please try again later', code: 'RATE_LIMIT_EXCEEDED' }
  }
};

/**
 * CORS configuration
 */
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ?
    process.env.ALLOWED_ORIGINS.split(',') :
    [
      'http://localhost:3000',
      'http://localhost:3001',
      'https://ecochain-j1nj.onrender.com',
      'https://ecochain07.netlify.app',
      'https://*.vercel.app'
    ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['X-Total-Count'],
  credentials: true,
  maxAge: 86400 // 24 hours
};

/**
 * Security headers configuration
 */
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' ws: wss: https://*.vercel.app;"
};

module.exports = {
  encrypt,
  decrypt,
  hash,
  generateSecureToken,
  sanitizeObject,
  rateLimits,
  corsOptions,
  securityHeaders
};