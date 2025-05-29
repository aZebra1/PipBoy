// pipboy-server.js
// Backend Server for Fallout TTRPG Pip Boy App

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallout-pipboy-secret-key';
const SALT_ROUNDS = 10;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files

// Database setup
const db = new sqlite3.Database('pipboy.db');

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Items table
    db.run(`
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            image_url TEXT DEFAULT '/api/placeholder/200/150',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // User inventory table
    db.run(`
        CREATE TABLE IF NOT EXISTS user_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_key TEXT NOT NULL,
            quantity INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, item_key)
        )
    `);

    // Party storage table
    db.run(`
        CREATE TABLE IF NOT EXISTS party_storage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_key TEXT UNIQUE NOT NULL,
            quantity INTEGER DEFAULT 1
        )
    `);

    // Quests table
    db.run(`
        CREATE TABLE IF NOT EXISTS quests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            quest_key TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            image_url TEXT DEFAULT '/api/placeholder/400/200',
            is_active BOOLEAN DEFAULT TRUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Map and marker table version 0.2.0 additions
    db.run(`
        CREATE TABLE IF NOT EXISTS map_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            x INTEGER NOT NULL,
            y INTEGER NOT NULL
        )
    `);


    // Insert default admin user and sample data
    const adminPassword = bcrypt.hashSync('admin', SALT_ROUNDS);
    db.run(`
        INSERT OR IGNORE INTO users (username, password_hash, is_admin) 
        VALUES ('gm', ?, TRUE)
    `, [adminPassword]);
});

// WebSocket connections for real-time updates
const clients = new Set();

wss.on('connection', (ws) => {
    console.log('New WebSocket connection');
    clients.add(ws);
    
    ws.on('close', () => {
        clients.delete(ws);
    });
});

// Broadcast to all connected clients
function broadcast(data) {
    const message = JSON.stringify(data);
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    });
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}

// Middleware to check admin privileges
function requireAdmin(req, res, next) {
    if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
    next();
}

// === AUTH ROUTES ===

// Register/Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            // Create new user
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            db.run(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                [username, hashedPassword],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to create user' });
                    }
                    
                    const token = jwt.sign(
                        { userId: this.lastID, username, isAdmin: false },
                        JWT_SECRET,
                        { expiresIn: '24h' }
                    );
                    
                    res.json({
                        token,
                        user: { id: this.lastID, username, isAdmin: false }
                    });
                }
            );
        } else {
            // Verify existing user
            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'Invalid password' });
            }

            const token = jwt.sign(
                { userId: user.id, username: user.username, isAdmin: user.is_admin },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                token,
                user: { id: user.id, username: user.username, isAdmin: user.is_admin }
            });
        }
    });
});

// === ITEM ROUTES ===

// Get all items
app.get('/api/items', authenticateToken, (req, res) => {
    db.all('SELECT * FROM items ORDER BY name', (err, items) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(items);
    });
});

// Add new item (admin only)
app.post('/api/items', authenticateToken, requireAdmin, (req, res) => {
    const { name, description, imageUrl } = req.body;
    
    if (!name || !description) {
        return res.status(400).json({ error: 'Name and description required' });
    }

    const itemKey = name.toLowerCase().replace(/\s+/g, '-');
    const image = imageUrl || '/api/placeholder/200/150';

    db.run(
        'INSERT INTO items (item_key, name, description, image_url) VALUES (?, ?, ?, ?)',
        [itemKey, name, description, image],
        function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(400).json({ error: 'Item already exists' });
                }
                return res.status(500).json({ error: 'Database error' });
            }
            
            const newItem = { id: this.lastID, item_key: itemKey, name, description, image_url: image };
            broadcast({ type: 'ITEM_ADDED', item: newItem });
            res.json(newItem);
        }
    );
});

// Delete item (admin only)
app.delete('/api/items/:itemKey', authenticateToken, requireAdmin, (req, res) => {
    const { itemKey } = req.params;

    db.run('DELETE FROM items WHERE item_key = ?', [itemKey], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }

        // Also remove from inventories and party storage
        db.run('DELETE FROM user_inventory WHERE item_key = ?', [itemKey]);
        db.run('DELETE FROM party_storage WHERE item_key = ?', [itemKey]);
        
        broadcast({ type: 'ITEM_DELETED', itemKey });
        res.json({ message: 'Item deleted successfully' });
    });
});

// === INVENTORY ROUTES ===

// Get user inventory
app.get('/api/inventory', authenticateToken, (req, res) => {
    db.all(`
        SELECT ui.item_key, ui.quantity, i.name, i.description, i.image_url
        FROM user_inventory ui
        JOIN items i ON ui.item_key = i.item_key
        WHERE ui.user_id = ?
        ORDER BY i.name
    `, [req.user.userId], (err, inventory) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(inventory);
    });
});

// Add item to inventory
app.post('/api/inventory', authenticateToken, (req, res) => {
    const { itemKey, quantity = 1 } = req.body;

    if (!itemKey) {
        return res.status(400).json({ error: 'Item key required' });
    }

    db.run(`
        INSERT INTO user_inventory (user_id, item_key, quantity) 
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, item_key) 
        DO UPDATE SET quantity = quantity + ?
    `, [req.user.userId, itemKey, quantity, quantity], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ message: 'Item added to inventory' });
    });
});

// Remove item from inventory
app.delete('/api/inventory/:itemKey', authenticateToken, (req, res) => {
    const { itemKey } = req.params;
    const quantity = parseInt(req.query.quantity) || 1;

    db.run(`
        UPDATE user_inventory 
        SET quantity = quantity - ? 
        WHERE user_id = ? AND item_key = ? AND quantity >= ?
    `, [quantity, req.user.userId, itemKey, quantity], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (this.changes > 0) {
            db.run(`
                DELETE FROM user_inventory 
                WHERE user_id = ? AND item_key = ? AND quantity <= 0
            `, [req.user.userId, itemKey], function(err2) {
                if (err2) {
                    return res.status(500).json({ error: 'Cleanup error' });
                }
                return res.json({ message: 'Item removed from inventory' });
            });
        } else {
            return res.status(400).json({ error: 'Nothing to remove or not enough quantity' });
        }
    });
});


// === PARTY STORAGE ROUTES ===

// Get party storage
app.get('/api/party-storage', authenticateToken, (req, res) => {
    db.all(`
        SELECT ps.item_key, ps.quantity, i.name, i.description, i.image_url
        FROM party_storage ps
        JOIN items i ON ps.item_key = i.item_key
        ORDER BY i.name
    `, (err, storage) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(storage);
    });
});

// Add item to party storage
app.post('/api/party-storage', authenticateToken, (req, res) => {
    const { itemKey, quantity = 1 } = req.body;

    if (!itemKey) {
        return res.status(400).json({ error: 'Item key required' });
    }

    db.run(`
        INSERT INTO party_storage (item_key, quantity) 
        VALUES (?, ?)
        ON CONFLICT(item_key) 
        DO UPDATE SET quantity = quantity + ?
    `, [itemKey, quantity, quantity], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        broadcast({ type: 'PARTY_STORAGE_UPDATED' });
        res.json({ message: 'Item added to party storage' });
    });
});

// Remove item from party storage
app.delete('/api/party-storage/:itemKey', authenticateToken, (req, res) => {
    const { itemKey } = req.params;
    const { quantity = 1 } = req.body;

    db.run(`
        UPDATE party_storage 
        SET quantity = quantity - ? 
        WHERE item_key = ? AND quantity > ?
    `, [quantity, itemKey, quantity], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (this.changes > 0) {
            // Remove items with 0 or negative quantity
            db.run(`
                DELETE FROM party_storage 
                WHERE item_key = ? AND quantity <= 0
            `, [itemKey]);
        }

        broadcast({ type: 'PARTY_STORAGE_UPDATED' });
        res.json({ message: 'Item removed from party storage' });
    });
});

// === QUEST ROUTES ===

// Get all active quests
app.get('/api/quests', authenticateToken, (req, res) => {
    db.all('SELECT * FROM quests WHERE is_active = TRUE ORDER BY created_at DESC', (err, quests) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(quests);
    });
});

app.get('/api/map', authenticateToken, (req, res) => { // version 0.2.0 additions
    db.all('SELECT * FROM map_data ORDER BY name', (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/map', authenticateToken, requireAdmin, (req, res) => { // version 0.2.0 additions
    const { name, x, y } = req.body;
    if (!name || x == null || y == null) {
        return res.status(400).json({ error: 'Name and coordinates required' });
    }
    db.run(`INSERT INTO map_data (name, x, y) VALUES (?, ?, ?)`, [name, x, y], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        broadcast({ type: 'MAP_UPDATED' });
        res.json({ id: this.lastID, name, x, y });
    });
});

app.delete('/api/map/:id', authenticateToken, requireAdmin, (req, res) => { // version 0.2.0 additions
    db.run(`DELETE FROM map_data WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        broadcast({ type: 'MAP_UPDATED' });
        res.json({ message: 'Marker deleted' });
    });
});




// Add new quest (admin only)
app.post('/api/quests', authenticateToken, requireAdmin, (req, res) => {
    const { name, description, imageUrl } = req.body;
    
    if (!name || !description) {
        return res.status(400).json({ error: 'Name and description required' });
    }

    const questKey = name.toLowerCase().replace(/\s+/g, '-');
    const image = imageUrl || '/api/placeholder/400/200';

    db.run(
        'INSERT INTO quests (quest_key, name, description, image_url) VALUES (?, ?, ?, ?)',
        [questKey, name, description, image],
        function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(400).json({ error: 'Quest already exists' });
                }
                return res.status(500).json({ error: 'Database error' });
            }
            
            const newQuest = { 
                id: this.lastID, 
                quest_key: questKey, 
                name, 
                description, 
                image_url: image,
                is_active: true
            };
            
            broadcast({ type: 'QUEST_ADDED', quest: newQuest });
            res.json(newQuest);
        }
    );
});

// Delete quest (admin only)
app.delete('/api/quests/:questKey', authenticateToken, requireAdmin, (req, res) => {
    const { questKey } = req.params;

    db.run('DELETE FROM quests WHERE quest_key = ?', [questKey], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Quest not found' });
        }

        broadcast({ type: 'QUEST_DELETED', questKey });
        res.json({ message: 'Quest deleted successfully' });
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Pip Boy Server running on port ${PORT}`);
    console.log(`📊 Database: pipboy.db`);
    console.log(`🌐 API Base URL: http://public-ip:${PORT}/api`);
    console.log(`🔌 WebSocket URL: ws://public-ip:${PORT}`);
	console.log(`❤️ Made by aZebra1`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n📴 Shutting down server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});