const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config(); // لاستخدام ملف .env

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_super_secret_key_that_is_long_and_random'; // الآن من ملف البيئة

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// التحقق من وجود مفتاح سري
if (!process.env.SECRET_KEY) {
  console.warn('⚠️  تحذير: لم يتم تعيين SECRET_KEY في ملف البيئة. يرجى إنشاء ملف .env مع مفتاح قوي.');
}

// إعداد قاعدة البيانات الدائمة
const db = new sqlite3.Database('db.sqlite3'); // الآن قاعدة بيانات دائمة وليس مؤقتة

db.serialize(() => {
    // إنشاء جداول المنتجات والمستخدمين
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, image_link TEXT, description TEXT, carat TEXT, weight REAL, price REAL, type TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS gold_prices (id INTEGER PRIMARY KEY AUTOINCREMENT, carat_21_buy REAL, carat_21_sell REAL, carat_22_buy REAL, carat_22_sell REAL, gram_1_buy REAL, gram_1_sell REAL, gram_5_buy REAL, gram_5_sell REAL, gram_10_buy REAL, gram_10_sell REAL, quarter_gold_buy REAL, quarter_gold_sell REAL, half_gold_buy REAL, half_gold_sell REAL, full_gold_buy REAL, full_gold_sell REAL)");
    db.run("CREATE TABLE IF NOT EXISTS currency_rates (id INTEGER PRIMARY KEY AUTOINCREMENT, usd_buy REAL, usd_sell REAL, eur_buy REAL, eur_sell REAL, sar_buy REAL, sar_sell REAL)");

    // التأكد من وجود سجل واحد فقط في جداول الأسعار
    db.get("SELECT COUNT(*) AS count FROM gold_prices", (err, row) => {
        if (row.count === 0) {
            db.run("INSERT INTO gold_prices (carat_21_buy, carat_21_sell, carat_22_buy, carat_22_sell, gram_1_buy, gram_1_sell, gram_5_buy, gram_5_sell, gram_10_buy, gram_10_sell, quarter_gold_buy, quarter_gold_sell, half_gold_buy, half_gold_sell, full_gold_buy, full_gold_sell) VALUES (55.5, 56.5, 58.5, 59.5, 56.5, 57.0, 282.5, 285.0, 565.0, 570.0, 141.25, 142.5, 282.5, 285.0, 565.0, 570.0)");
        }
    });

    db.get("SELECT COUNT(*) AS count FROM currency_rates", (err, row) => {
        if (row.count === 0) {
            db.run("INSERT INTO currency_rates (usd_buy, usd_sell, eur_buy, eur_sell, sar_buy, sar_sell) VALUES (1.0, 1.1, 1.2, 1.3, 0.2, 0.25)");
        }
    });

    // إضافة مستخدم مسؤول (admin) افتراضي إذا لم يكن موجودًا
    db.get("SELECT * FROM users WHERE username = 'admin'", (err, user) => {
        if (!user) {
            const salt = bcrypt.genSaltSync(10);
            const hashedPassword = bcrypt.hashSync('admin123', salt);
            db.run("INSERT INTO users (username, password) VALUES (?, ?)", ['admin', hashedPassword], (err) => {
                if (err) {
                    console.error('Failed to create admin user:', err.message);
                } else {
                    console.log('Admin user created successfully!');
                }
            });
        }
    });
});

// دالة للتحقق من صحة روابط الصور
function isValidImageUrl(url) {
    try {
        const parsedUrl = new URL(url);
        return ['http:', 'https:'].includes(parsedUrl.protocol) && 
               !url.includes('javascript:');
    } catch (e) {
        return false;
    }
}

// Middleware للتحقق من التوكن (Token)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ error: 'Unauthorized: No token provided' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden: Invalid token' });
        req.user = user;
        next();
    });
};

// مسار تسجيل الدخول (Login Endpoint)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ username: user.username, id: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// --- مسارات عامة (يمكن للزوار الوصول إليها بدون توكن) ---
app.get('/api/products', (req, res) => {
    db.all("SELECT * FROM products", [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.get('/api/gold-prices', (req, res) => {
    db.get("SELECT * FROM gold_prices WHERE id = 1", [], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(row);
    });
});

app.get('/api/currency-rates', (req, res) => {
    db.get("SELECT * FROM currency_rates WHERE id = 1", [], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(row);
    });
});

// --- مسارات إدارية (تتطلب توكن) ---
app.post('/api/products', authenticateToken, (req, res) => {
    const { name, image_link, description, carat, weight, price, type } = req.body;
    
    // التحقق من صحة المدخلات
    if (!name || !image_link || !description || !carat || weight <= 0 || price <= 0 || !type) {
        return res.status(400).json({ error: 'All fields are required and must have valid values' });
    }
    
    // التحقق من صحة رابط الصورة
    if (!isValidImageUrl(image_link)) {
        return res.status(400).json({ error: 'Invalid image URL' });
    }
    
    db.run("INSERT INTO products (name, image_link, description, carat, weight, price, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [name, image_link, description, carat, weight, price, type], function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ id: this.lastID, message: 'Product added successfully!' });
        });
});

app.put('/api/products/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { name, image_link, description, carat, weight, price, type } = req.body;
    
    // التحقق من صحة المدخلات
    if (!name || !image_link || !description || !carat || weight <= 0 || price <= 0 || !type) {
        return res.status(400).json({ error: 'All fields are required and must have valid values' });
    }
    
    // التحقق من صحة رابط الصورة
    if (!isValidImageUrl(image_link)) {
        return res.status(400).json({ error: 'Invalid image URL' });
    }
    
    db.run("UPDATE products SET name = ?, image_link = ?, description = ?, carat = ?, weight = ?, price = ?, type = ? WHERE id = ?",
        [name, image_link, description, carat, weight, price, type, id], (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Product not found' });
            }
            res.json({ message: 'Product updated successfully!' });
        });
});

app.delete('/api/products/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.run("DELETE FROM products WHERE id = ?", id, function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json({ message: 'Product deleted successfully!' });
    });
});

app.put('/api/gold-prices', authenticateToken, (req, res) => {
    const { carat_21_buy, carat_21_sell, carat_22_buy, carat_22_sell, gram_1_buy, gram_1_sell, gram_5_buy, gram_5_sell, gram_10_buy, gram_10_sell, quarter_gold_buy, quarter_gold_sell, half_gold_buy, half_gold_sell, full_gold_buy, full_gold_sell } = req.body;
    
    // التحقق من صحة المدخلات
    const prices = [carat_21_buy, carat_21_sell, carat_22_buy, carat_22_sell, gram_1_buy, gram_1_sell, gram_5_buy, gram_5_sell, gram_10_buy, gram_10_sell, quarter_gold_buy, quarter_gold_sell, half_gold_buy, half_gold_sell, full_gold_buy, full_gold_sell];
    if (prices.some(price => price === undefined || price < 0)) {
        return res.status(400).json({ error: 'All price fields are required and must be non-negative' });
    }
    
    db.run("UPDATE gold_prices SET carat_21_buy = ?, carat_21_sell = ?, carat_22_buy = ?, carat_22_sell = ?, gram_1_buy = ?, gram_1_sell = ?, gram_5_buy = ?, gram_5_sell = ?, gram_10_buy = ?, gram_10_sell = ?, quarter_gold_buy = ?, quarter_gold_sell = ?, half_gold_buy = ?, half_gold_sell = ?, full_gold_buy = ?, full_gold_sell = ? WHERE id = 1",
        [carat_21_buy, carat_21_sell, carat_22_buy, carat_22_sell, gram_1_buy, gram_1_sell, gram_5_buy, gram_5_sell, gram_10_buy, gram_10_sell, quarter_gold_buy, quarter_gold_sell, half_gold_buy, half_gold_sell, full_gold_buy, full_gold_sell], (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Gold prices updated successfully!' });
        });
});

app.put('/api/currency-rates', authenticateToken, (req, res) => {
    const { usd_buy, usd_sell, eur_buy, eur_sell, sar_buy, sar_sell } = req.body;
    
    // التحقق من صحة المدخلات
    const rates = [usd_buy, usd_sell, eur_buy, eur_sell, sar_buy, sar_sell];
    if (rates.some(rate => rate === undefined || rate < 0)) {
        return res.status(400).json({ error: 'All rate fields are required and must be non-negative' });
    }
    
    db.run("UPDATE currency_rates SET usd_buy = ?, usd_sell = ?, eur_buy = ?, eur_sell = ?, sar_buy = ?, sar_sell = ? WHERE id = 1",
        [usd_buy, usd_sell, eur_buy, eur_sell, sar_buy, sar_sell], (err) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'Currency rates updated successfully!' });
        });
});

// مسار عرض الملفات
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// صفحة 404
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

app.listen(PORT, () => {
    console.log(`\n✅ الخادم يعمل على http://localhost:${PORT}`);
    console.log('ℹ️  ملاحظة: الزوار يمكنهم رؤية الموقع بدون تسجيل دخول');
    console.log('ℹ️  التسجيل مطلوب فقط للتعديل على المحتوى (المنتجات والأسعار)');
    console.log('ℹ️  لاستخدام لوحة التحكم، اذهب إلى /admin\n');
});