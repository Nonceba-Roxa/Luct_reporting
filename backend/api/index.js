require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const serverless = require('serverless-http'); // ← ADD THIS

const app = express();
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-frontend.vercel.app'],
  credentials: true
}));

// Database pool
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password: process.env.MYSQLPASSWORD || process.env.DB_PASS,
  database: process.env.MYSQLDATABASE || process.env.DB_NAME,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ✅ ADD THIS ROOT ROUTE - FIXES "Cannot GET /"
app.get('/', (req, res) => {
  res.json({ message: 'LUCT Backend API is running on Vercel 🚀' });
});

// ✅ ADD THIS HEALTH CHECK ROUTE
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Test DB connection endpoint
app.get('/test-db', (req, res) => {
  pool.query('SELECT 1', (err) => {
    if (err) {
      console.error('DB connection test failed:', err);
      return res.status(500).json({ message: 'DB connection failed', error: err.message });
    }
    res.json({ message: 'DB connected successfully' });
  });
});

// Middleware to verify JWT with logging
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err.message);
      return res.status(403).json({ message: 'Invalid or expired token', error: err.message });
    }
    console.log('Authenticated user:', user); // Debug log
    req.user = user;
    next();
  });
};

// Register (no change)
app.post('/register', (req, res) => {
  const { username, password, role, stream } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  pool.query('INSERT INTO users (username, password, role, stream) VALUES (?, ?, ?, ?)', [username, hashedPassword, role, stream], (err) => {
    if (err) {
      console.error('Register error:', err);
      return res.status(500).json({ message: 'Error registering', error: err.message });
    }
    res.json({ message: 'Registered' });
  });
});

// Login (increased expiration to 24h)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  pool.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error('Login query error:', err);
      return res.status(500).json({ message: 'Server error', error: err.message });
    }
    if (results.length === 0) return res.status(400).json({ message: 'Invalid credentials' });
    const user = results[0];
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role, stream: user.stream }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, role: user.role });
  });
});

// Get user profile
app.get('/profile', authenticate, (req, res) => {
  pool.query('SELECT id, username, role, stream FROM users WHERE id = ?', [req.user.id], (err, results) => {
    if (err) {
      console.error('Profile query error:', err);
      return res.status(500).json({ message: 'Error fetching profile', error: err.message });
    }
    res.json(results[0] || {});
  });
});

// Get all lecturers (for PL assignment dropdown)
app.get('/users/lecturers', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden' });
  pool.query('SELECT id, username FROM users WHERE role = "lecturer"', (err, results) => {
    if (err) {
      console.error('Lecturers query error:', err);
      return res.status(500).json({ message: 'Error fetching lecturers', error: err.message });
    }
    console.log('Fetched lecturers:', results); // Debug
    res.json(results || []);
  });
});

// Courses APIs
app.get('/courses', authenticate, (req, res) => {
  let query = 'SELECT * FROM courses';
  let params = [];
  if (req.user.role === 'prl' || req.user.role === 'lecturer') {
    query += ' WHERE stream = ?';
    params = [req.user.stream || '']; // Handle null stream
  }
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Courses query error:', err);
      return res.status(500).json({ message: 'Error fetching courses', error: err.message });
    }
    res.json(results || []);
  });
});

app.post('/courses', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden' });
  const { name, code, stream, description } = req.body;
  pool.query('INSERT INTO courses (name, code, stream, description) VALUES (?, ?, ?, ?)', [name, code, stream, description], (err) => {
    if (err) {
      console.error('Add course error:', err);
      return res.status(500).json({ message: 'Error adding course', error: err.message });
    }
    res.json({ message: 'Course added' });
  });
});

// Assign lecturer
app.post('/assign-lecturer', authenticate, (req, res) => {
  if (req.user.role !== 'pl') return res.status(403).json({ message: 'Forbidden' });
  const { course_id, lecturer_id, venue, scheduled_time, total_students, stream } = req.body;
  pool.query('INSERT INTO classes (course_id, lecturer_id, venue, scheduled_time, total_students, stream) VALUES (?, ?, ?, ?, ?, ?)', [course_id, lecturer_id, venue, scheduled_time, total_students, stream], (err) => {
    if (err) {
      console.error('Assign lecturer error:', err);
      return res.status(500).json({ message: 'Error assigning', error: err.message });
    }
    res.json({ message: 'Assigned' });
  });
});

// Get classes
app.get('/classes', authenticate, (req, res) => {
  let query = 'SELECT c.*, co.name as course_name, u.username as lecturer_name FROM classes c JOIN courses co ON c.course_id = co.id JOIN users u ON c.lecturer_id = u.id';
  let params = [];
  if (req.user.role === 'lecturer') {
    query += ' WHERE c.lecturer_id = ?';
    params = [req.user.id];
  } else if (req.user.role === 'prl') {
    query += ' WHERE c.stream = ?';
    params = [req.user.stream || ''];
  }
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Classes query error:', err);
      return res.status(500).json({ message: 'Error fetching classes', error: err.message });
    }
    res.json(results || []);
  });
});

// Submit report
app.post('/reports', authenticate, (req, res) => {
  if (req.user.role !== 'lecturer') return res.status(403).json({ message: 'Forbidden' });
  const { class_id, week, date, topic, learning_outcomes, present_students, total_students, venue, scheduled_time, recommendations } = req.body;
  pool.query(
    'INSERT INTO reports (lecturer_id, class_id, week, date, topic, learning_outcomes, present_students, total_students, venue, scheduled_time, recommendations) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, class_id, week, date, topic, learning_outcomes, present_students, total_students, venue, scheduled_time, recommendations],
    (err) => {
      if (err) {
        console.error('Submit report error:', err);
        return res.status(500).json({ message: 'Error submitting report', error: err.message });
      }
      res.json({ message: 'Report submitted' });
    }
  );
});

// Get reports
app.get('/reports', authenticate, (req, res) => {
  let query = 'SELECT r.*, u.username as lecturer_name, co.name as course_name FROM reports r JOIN users u ON r.lecturer_id = u.id JOIN classes cl ON r.class_id = cl.id JOIN courses co ON cl.course_id = co.id';
  let params = [];
  if (req.user.role === 'lecturer') {
    query += ' WHERE r.lecturer_id = ?';
    params = [req.user.id];
  } else if (req.user.role === 'prl') {
    query += ' WHERE cl.stream = ?';
    params = [req.user.stream || ''];
  }
  const { search, week, course } = req.query;
  if (search) {
    query += params.length ? ' AND' : ' WHERE';
    query += ' (co.name LIKE ? OR u.username LIKE ?)';
    params.push(`%${search}%`, `%${search}%`);
  }
  if (week) {
    query += params.length ? ' AND' : ' WHERE';
    query += ' r.week = ?';
    params.push(week);
  }
  if (course) {
    query += params.length ? ' AND' : ' WHERE';
    query += ' co.id = ?';
    params.push(course);
  }
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Reports query error:', err);
      return res.status(500).json({ message: 'Error fetching reports', error: err.message });
    }
    res.json(results || []);
  });
});

// Add PRL feedback
app.put('/reports/:id/feedback', authenticate, (req, res) => {
  if (req.user.role !== 'prl') return res.status(403).json({ message: 'Forbidden' });
  const { feedback } = req.body;
  pool.query('UPDATE reports SET prl_feedback = ?, status = "reviewed" WHERE id = ?', [feedback, req.params.id], (err) => {
    if (err) {
      console.error('Feedback update error:', err);
      return res.status(500).json({ message: 'Error adding feedback', error: err.message });
    }
    res.json({ message: 'Feedback added' });
  });
});

// Ratings APIs
app.post('/ratings', authenticate, (req, res) => {
  const { ratee_id, rating, comment, type } = req.body;
  if (req.user.role === 'student' && type !== 'student_to_lecturer') return res.status(403).json({ message: 'Forbidden' });
  pool.query('INSERT INTO ratings (rater_id, ratee_id, rating, comment, type) VALUES (?, ?, ?, ?, ?)', [req.user.id, ratee_id, rating, comment, type], (err) => {
    if (err) {
      console.error('Submit rating error:', err);
      return res.status(500).json({ message: 'Error submitting rating', error: err.message });
    }
    res.json({ message: 'Rating submitted' });
  });
});

// Ratings (updated to include lecturer_to_facilities for lecturers)
app.get('/ratings', authenticate, (req, res) => {
  let query = 'SELECT * FROM ratings';
  let params = [];
  if (req.user.role === 'lecturer') {
    query += ' WHERE (ratee_id = ? AND type = "student_to_lecturer") OR (rater_id = ? AND type = "lecturer_to_facilities")';
    params = [req.user.id, req.user.id];
  } else if (req.user.role === 'prl') {
    query += ' WHERE type IN ("student_to_lecturer", "lecturer_to_facilities")';
  }
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Ratings query error:', err);
      return res.status(500).json({ message: 'Error fetching ratings', error: err.message });
    }
    console.log('Fetched ratings:', results); // Debug
    res.json(results || []);
  });
});

// Monitoring (updated query to handle empty/zero data)
app.get('/monitoring', authenticate, (req, res) => {
  let query = 'SELECT IFNULL(AVG(present_students / NULLIF(total_students, 0) * 100), 0) as avg_attendance, COUNT(*) as report_count FROM reports';
  let params = [];
  if (req.user.role === 'lecturer') {
    query += ' WHERE lecturer_id = ?';
    params = [req.user.id];
  } else if (req.user.role === 'prl') {
    query += ' WHERE EXISTS (SELECT 1 FROM classes cl JOIN courses co ON cl.course_id = co.id WHERE cl.id = reports.class_id AND co.stream = ?)';
    params = [req.user.stream || 'Information Technology'];
  }
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Monitoring query error:', err);
      return res.status(500).json({ message: 'Error fetching monitoring data', error: err.message });
    }
    console.log('Monitoring data:', results[0]); // Debug
    res.json(results[0] || { avg_attendance: 0, report_count: 0 });
  });
});

module.exports = serverless(app);