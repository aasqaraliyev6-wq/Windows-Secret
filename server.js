const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// ==================== KONFIGURATSIYA ====================
const CONFIG = {
    JWT_SECRET: process.env.JWT_SECRET || 'quvnoq-cyber-secret-key-2024',
    BCRYPT_ROUNDS: 12,
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 soat
    MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
    UPLOAD_DIR: 'uploads',
    BACKUP_DIR: 'backups'
};

// ==================== MIDDLEWARELAR ====================

// Xavfsizlik middlewarelari
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Compression
app.use(compression());

// Logging
app.use(morgan('combined'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 daqiqa
    max: 100, // har IP uchun 100 ta so'rov
    message: {
        error: "Too many requests from this IP, please try again later."
    }
});
app.use(limiter);

// JSON parser with limit
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files with cache control
app.use(express.static('public', {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

// ==================== MA'LUMOTLAR BAZASI (File-based) ====================

const DB_FILE = 'database.json';

function readDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
        }
    } catch (error) {
        console.error('Database read error:', error);
    }
    return {
        users: [],
        emails: [],
        contacts: [],
        files: [],
        sessions: [],
        activityLogs: [],
        settings: {}
    };
}

function writeDatabase(data) {
    try {
        // Backup yaratish
        if (fs.existsSync(DB_FILE)) {
            const backupDir = CONFIG.BACKUP_DIR;
            if (!fs.existsSync(backupDir)) {
                fs.mkdirSync(backupDir, { recursive: true });
            }
            const backupFile = path.join(backupDir, `backup-${Date.now()}.json`);
            fs.copyFileSync(DB_FILE, backupFile);
        }

        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        console.error('Database write error:', error);
        return false;
    }
}

// ==================== YORDAMCHI FUNKSIYALAR ====================

function generateToken(userId) {
    return jwt.sign({ userId, timestamp: Date.now() }, CONFIG.JWT_SECRET, {
        expiresIn: '24h'
    });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, CONFIG.JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function hashPassword(password) {
    return bcrypt.hashSync(password, CONFIG.BCRYPT_ROUNDS);
}

function verifyPassword(password, hash) {
    return bcrypt.compareSync(password, hash);
}

function logActivity(userId, action, details) {
    const db = readDatabase();
    db.activityLogs.unshift({
        id: generateId(),
        userId,
        action,
        details,
        timestamp: new Date().toISOString(),
        ip: req.ip
    });

    // Faqat oxirgi 1000 ta logni saqlash
    if (db.activityLogs.length > 1000) {
        db.activityLogs = db.activityLogs.slice(0, 1000);
    }

    writeDatabase(db);
}

function generateId() {
    return crypto.randomBytes(16).toString('hex');
}

function sanitizeInput(input) {
    if (typeof input === 'string') {
        return input.replace(/[<>&"']/g, '');
    }
    return input;
}

// ==================== AUTH MIDDLEWARE ====================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.userId = decoded.userId;
    next();
}

// ==================== ROUTES ====================

// Asosiy route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        version: '1.0.0'
    });
});

// ==================== AUTH ROUTES ====================

// Ro'yxatdan o'tish
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const db = readDatabase();
        
        // Email tekshirish
        const existingUser = db.users.find(user => user.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Yangi foydalanuvchi yaratish
        const newUser = {
            id: generateId(),
            email: sanitizeInput(email),
            password: hashPassword(password),
            name: sanitizeInput(name || ''),
            createdAt: new Date().toISOString(),
            isActive: true,
            lastLogin: null
        };

        db.users.push(newUser);
        
        if (writeDatabase(db)) {
            const token = generateToken(newUser.id);
            
            logActivity(newUser.id, 'REGISTER', 'New user registration');
            
            res.json({
                success: true,
                token,
                user: {
                    id: newUser.id,
                    email: newUser.email,
                    name: newUser.name
                }
            });
        } else {
            res.status(500).json({ error: 'Database error' });
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login
app.post('/api/login', (req, res) => {
    try {
        const { email, password, rememberMe } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const db = readDatabase();
        const user = db.users.find(u => u.email === email && u.isActive);
        
        if (!user || !verifyPassword(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Yangi login vaqti
        user.lastLogin = new Date().toISOString();
        writeDatabase(db);

        const token = generateToken(user.id);
        
        logActivity(user.id, 'LOGIN', 'User logged in');

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Profilni yangilash
app.put('/api/profile', authenticateToken, (req, res) => {
    try {
        const { name, currentPassword, newPassword } = req.body;
        const db = readDatabase();
        
        const userIndex = db.users.findIndex(u => u.id === req.userId);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }

        const user = db.users[userIndex];

        // Parolni yangilash
        if (newPassword) {
            if (!currentPassword || !verifyPassword(currentPassword, user.password)) {
                return res.status(400).json({ error: 'Current password is incorrect' });
            }
            user.password = hashPassword(newPassword);
        }

        // Ismni yangilash
        if (name) {
            user.name = sanitizeInput(name);
        }

        db.users[userIndex] = user;
        
        if (writeDatabase(db)) {
            logActivity(req.userId, 'PROFILE_UPDATE', 'User profile updated');
            res.json({ success: true, user: { id: user.id, email: user.email, name: user.name } });
        } else {
            res.status(500).json({ error: 'Database error' });
        }
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== EMAIL ROUTES ====================

// Email lar ro'yxati
app.get('/api/emails', authenticateToken, (req, res) => {
    try {
        const { folder, page = 1, limit = 20, search } = req.query;
        const db = readDatabase();
        
        let emails = db.emails.filter(email => 
            email.to === req.userId || email.from === req.userId
        );

        // Papka bo'yicha filtrlash
        if (folder && folder !== 'all') {
            emails = emails.filter(email => email.folder === folder);
        }

        // Qidiruv
        if (search) {
            const searchTerm = search.toLowerCase();
            emails = emails.filter(email => 
                email.subject.toLowerCase().includes(searchTerm) ||
                email.body.toLowerCase().includes(searchTerm) ||
                email.from.toLowerCase().includes(searchTerm) ||
                email.to.toLowerCase().includes(searchTerm)
            );
        }

        // Saralash (yangi -> eski)
        emails.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        // Pagination
        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + parseInt(limit);
        const paginatedEmails = emails.slice(startIndex, endIndex);

        res.json({
            emails: paginatedEmails,
            total: emails.length,
            page: parseInt(page),
            totalPages: Math.ceil(emails.length / limit)
        });
    } catch (error) {
        console.error('Get emails error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Yangi email yuborish
app.post('/api/emails', authenticateToken, (req, res) => {
    try {
        const { to, subject, body, cc, bcc } = req.body;
        
        if (!to || !subject || !body) {
            return res.status(400).json({ error: 'To, subject and body are required' });
        }

        const db = readDatabase();
        
        const newEmail = {
            id: generateId(),
            from: req.userId,
            to: sanitizeInput(to),
            subject: sanitizeInput(subject),
            body: sanitizeInput(body),
            cc: cc ? sanitizeInput(cc) : '',
            bcc: bcc ? sanitizeInput(bcc) : '',
            timestamp: new Date().toISOString(),
            read: false,
            starred: false,
            folder: 'sent',
            attachments: []
        };

        db.emails.unshift(newEmail);
        
        if (writeDatabase(db)) {
            logActivity(req.userId, 'EMAIL_SENT', `Email sent to ${to}`);
            
            res.json({
                success: true,
                email: newEmail
            });
        } else {
            res.status(500).json({ error: 'Database error' });
        }
    } catch (error) {
        console.error('Send email error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Email ni o'chirish
app.delete('/api/emails/:id', authenticateToken, (req, res) => {
    try {
        const { id } = req.params;
        const db = readDatabase();
        
        const emailIndex = db.emails.findIndex(email => 
            email.id === id && (email.from === req.userId || email.to === req.userId)
        );

        if (emailIndex === -1) {
            return res.status(404).json({ error: 'Email not found' });
        }

        db.emails.splice(emailIndex, 1);
        
        if (writeDatabase(db)) {
            logActivity(req.userId, 'EMAIL_DELETED', `Email ${id} deleted`);
            res.json({ success: true });
        } else {
            res.status(500).json({ error: 'Database error' });
        }
    } catch (error) {
        console.error('Delete email error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== CONTACTS ROUTES ====================

// Kontaktlar ro'yxati
app.get('/api/contacts', authenticateToken, (req, res) => {
    try {
        const db = readDatabase();
        const userContacts = db.contacts.filter(contact => contact.userId === req.userId);
        res.json({ contacts: userContacts });
    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Yangi kontakt qo'shish
app.post('/api/contacts', authenticateToken, (req, res) => {
    try {
        const { name, email, phone, company } = req.body;
        
        if (!name || !email) {
            return res.status(400).json({ error: 'Name and email are required' });
        }

        const db = readDatabase();
        
        const newContact = {
            id: generateId(),
            userId: req.userId,
            name: sanitizeInput(name),
            email: sanitizeInput(email),
            phone: sanitizeInput(phone || ''),
            company: sanitizeInput(company || ''),
            createdAt: new Date().toISOString()
        };

        db.contacts.push(newContact);
        
        if (writeDatabase(db)) {
            logActivity(req.userId, 'CONTACT_ADDED', `Contact ${name} added`);
            res.json({ success: true, contact: newContact });
        } else {
            res.status(500).json({ error: 'Database error' });
        }
    } catch (error) {
        console.error('Add contact error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== FILE ROUTES ====================

// Upload papkasini yaratish
if (!fs.existsSync(CONFIG.UPLOAD_DIR)) {
    fs.mkdirSync(CONFIG.UPLOAD_DIR, { recursive: true });
}

// Fayl yuklash
app.post('/api/upload', authenticateToken, (req, res) => {
    // Bu endpoint mulim media yuklash uchun
    // Haqiqiy fayl yuklash uchun mulim-form dan foydalanish kerak
    res.json({ message: 'File upload endpoint - use multipart/form-data' });
});

// ==================== ADMIN ROUTES ====================

// Activity loglari (faqat admin uchun)
app.get('/api/admin/activity', authenticateToken, (req, res) => {
    try {
        const db = readDatabase();
        const { page = 1, limit = 50 } = req.query;
        
        const startIndex = (page - 1) * limit;
        const logs = db.activityLogs.slice(startIndex, startIndex + parseInt(limit));
        
        res.json({
            logs,
            total: db.activityLogs.length,
            page: parseInt(page),
            totalPages: Math.ceil(db.activityLogs.length / limit)
        });
    } catch (error) {
        console.error('Get activity logs error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// System statistikasi
app.get('/api/admin/stats', authenticateToken, (req, res) => {
    try {
        const db = readDatabase();
        
        const stats = {
            totalUsers: db.users.length,
            totalEmails: db.emails.length,
            totalContacts: db.contacts.length,
            activeUsers: db.users.filter(u => u.isActive).length,
            storageUsed: calculateStorageUsage(),
            serverUptime: process.uptime(),
            lastBackup: getLastBackupTime()
        };

        res.json(stats);
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ==================== YORDAMCHI FUNKSIYALAR ====================

function calculateStorageUsage() {
    let totalSize = 0;
    
    // Database fayl hajmi
    if (fs.existsSync(DB_FILE)) {
        totalSize += fs.statSync(DB_FILE).size;
    }
    
    // Upload papkasi hajmi
    if (fs.existsSync(CONFIG.UPLOAD_DIR)) {
        const files = fs.readdirSync(CONFIG.UPLOAD_DIR);
        files.forEach(file => {
            totalSize += fs.statSync(path.join(CONFIG.UPLOAD_DIR, file)).size;
        });
    }
    
    return totalSize;
}

function getLastBackupTime() {
    const backupDir = CONFIG.BACKUP_DIR;
    if (!fs.existsSync(backupDir)) {
        return null;
    }
    
    const files = fs.readdirSync(backupDir)
        .filter(file => file.startsWith('backup-'))
        .map(file => ({
            name: file,
            time: fs.statSync(path.join(backupDir, file)).mtime
        }))
        .sort((a, b) => b.time - a.time);
    
    return files.length > 0 ? files[0].time : null;
}

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// ==================== SERVER START ====================

app.listen(port, '0.0.0.0', () => {
    console.log(`🚀 Advanced Cyber Server running at http://localhost:${port}`);
    console.log(`📊 API endpoints available at http://localhost:${port}/api`);
    console.log(`🔐 JWT Secret: ${CONFIG.JWT_SECRET ? 'Set' : 'Using default'}`);
    console.log(`💾 Database: ${DB_FILE}`);
    console.log(`📁 Upload directory: ${CONFIG.UPLOAD_DIR}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Server shutting down gracefully...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Server shutting down gracefully...');
    process.exit(0);
});
