import type { Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';

// Configuración de CORS
export const corsConfig = cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://yourdomain.com', 'https://api.yourdomain.com'] 
    : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:3002'],
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
});

// Configuración de Helmet para seguridad
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "data:"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Rate limiting general
export const generalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '0'), // 15 minutos
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100'), // 100 requests por ventana
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      success: false,
      message: 'Too many requests from this IP, please try again later.',
      retryAfter: '15 minutes'
    });
  }
});

// Rate limiting más estricto para creación de clientes
// Sin límite para la creación de clientes (deshabilitado)
export const createCustomerRateLimit = (req: Request, res: Response, next: NextFunction): void => {
  next();
};

// Middleware para validar Content-Type en requests con body
export const validateContentType = (req: Request, res: Response, next: NextFunction): void => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    if (!req.headers['content-type']?.includes('application/json')) {
      res.status(400).json({
        success: false,
        message: 'Content-Type must be application/json'
      });
      return;
    }
  }
  next();
};

// Middleware para logging de seguridad
export const securityLogger = (req: Request, res: Response, next: NextFunction): void => {
  // Log requests sospechosos
  const suspiciousPatterns = [
    /select.*from/i,
    /union.*select/i,
    /script.*src/i,
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i,
    /eval\(/i,
    /alert\(/i
  ];

  const requestData = JSON.stringify({
    url: req.originalUrl,
    method: req.method,
    body: req.body,
    query: req.query,
    headers: req.headers
  });

  const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(requestData));

  if (isSuspicious) {
    console.warn(`🚨 SUSPICIOUS REQUEST detected from ${req.ip}:`, {
      method: req.method,
      url: req.originalUrl,
      userAgent: req.headers['user-agent'],
      body: req.body,
      timestamp: new Date().toISOString()
    });
  }

  next();
};

// Middleware de sanitización básica
export const sanitizeInput = (req: Request, res: Response, next: NextFunction): void => {
  const sanitizeValue = (value: any): any => {
    if (typeof value === 'string') {
      // Remover scripts básicos y caracteres peligrosos
      return value
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '')
        .replace(/on\w+\s*=/gi, '')
        .trim();
    } else if (typeof value === 'object' && value !== null) {
      const sanitizedObj: any = Array.isArray(value) ? [] : {};
      for (const key in value) {
        if (Object.prototype.hasOwnProperty.call(value, key)) {
          sanitizedObj[key] = sanitizeValue(value[key]);
        }
      }
      return sanitizedObj;
    }
    return value;
  };

  if (req.body) {
    req.body = sanitizeValue(req.body);
  }
  if (req.query && Object.keys(req.query).length > 0) {
    const sanitizedQuery = sanitizeValue(req.query);
    // Reemplazar cada propiedad individualmente ya que req.query es readonly
    for (const key in req.query) {
      if (Object.prototype.hasOwnProperty.call(req.query, key) && Object.prototype.hasOwnProperty.call(sanitizedQuery, key)) {
        (req.query as any)[key] = sanitizedQuery[key];
      }
    }
  }

  next();
};

// Middleware para headers de seguridad adicionales
export const additionalSecurityHeaders = (req: Request, res: Response, next: NextFunction): void => {
  // Prevenir información de versión del servidor
  res.removeHeader('X-Powered-By');
  
  // Headers adicionales de seguridad
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  
  next();
};

// Middleware combinado de seguridad
export const securityMiddleware = [
  corsConfig,
  helmetConfig,
  additionalSecurityHeaders,
  validateContentType,
  sanitizeInput,
  securityLogger
];