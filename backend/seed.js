const mysql = require('mysql2');
const bcrypt = require('bcryptjs');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'luct_reporting'
});

connection.connect(err => {
  if (err) {
    console.error('Failed to connect to MySQL:', err);
    throw err;
  }
  console.log('Connected to MySQL');

  const hashedPassword = bcrypt.hashSync('password123', 10);

  // Clear existing data
  connection.query('SET FOREIGN_KEY_CHECKS = 0', err => {
    if (err) console.error('Error disabling foreign keys:', err);
    connection.query('TRUNCATE TABLE ratings', err => { if (err) console.error('Error truncating ratings:', err); });
    connection.query('TRUNCATE TABLE reports', err => { if (err) console.error('Error truncating reports:', err); });
    connection.query('TRUNCATE TABLE classes', err => { if (err) console.error('Error truncating classes:', err); });
    connection.query('TRUNCATE TABLE courses', err => { if (err) console.error('Error truncating courses:', err); });
    connection.query('TRUNCATE TABLE users', err => { if (err) console.error('Error truncating users:', err); });
    connection.query('SET FOREIGN_KEY_CHECKS = 1', err => { if (err) console.error('Error enabling foreign keys:', err); });
  });

  // Seed users
  const users = [
    ['student1', hashedPassword, 'student', null],
    ['lecturer1', hashedPassword, 'lecturer', 'Information Technology'],
    ['lecturer2', hashedPassword, 'lecturer', 'Computer Science'],
    ['prl1', hashedPassword, 'prl', 'Information Technology'],
    ['pl1', hashedPassword, 'pl', null]
  ];
  connection.query('INSERT INTO users (username, password, role, stream) VALUES ?', [users], err => {
    if (err) console.error('Error seeding users:', err);
    else console.log('Seeded users');
  });

  // Seed courses
  const courses = [
    ['Web Development', 'DIWA2110', 'Information Technology'],
    ['Database Systems', 'DBS101', 'Computer Science']
  ];
  connection.query('INSERT INTO courses (name, code, stream) VALUES ?', [courses], err => {
    if (err) console.error('Error seeding courses:', err);
    else console.log('Seeded courses');
  });

  // Seed classes (course_id=1, lecturer_id=2; course_id=2, lecturer_id=3)
  const classes = [
    [1, 2, 'Room 101', 'Monday 10:00-12:00', 30, 'Information Technology'],
    [2, 3, 'Room 102', 'Tuesday 14:00-16:00', 25, 'Computer Science']
  ];
  connection.query('INSERT INTO classes (course_id, lecturer_id, venue, scheduled_time, total_students, stream) VALUES ?', [classes], err => {
    if (err) console.error('Error seeding classes:', err);
    else console.log('Seeded classes');
  });

  // Seed reports (lecturer_id=2, class_id=1; lecturer_id=3, class_id=2)
  const reports = [
    [2, 1, 1, '2025-09-01', 'Intro to Web', 'Understand HTML/CSS', 25, 30, 'Room 101', 'Monday 10:00-12:00', 'More practice'],
    [3, 2, 1, '2025-09-02', 'DB Basics', 'Learn SQL', 20, 25, 'Room 102', 'Tuesday 14:00-16:00', 'Good engagement']
  ];
  connection.query('INSERT INTO reports (lecturer_id, class_id, week, date, topic, learning_outcomes, present_students, total_students, venue, scheduled_time, recommendations) VALUES ?', [reports], err => {
    if (err) console.error('Error seeding reports:', err);
    else console.log('Seeded reports');
  });

// Seed ratings (lecturer_to_facilities by lecturer1 and lecturer2)
  const ratings = [
    [2, null, 4, 'Good classroom facilities', 'lecturer_to_facilities'],
    [3, null, 3, 'Projector needs repair', 'lecturer_to_facilities']
  ];
  connection.query('INSERT INTO ratings (rater_id, ratee_id, rating, comment, type) VALUES ?', [ratings], err => {
    if (err) console.error('Error seeding ratings:', err);
    else console.log('Seeded ratings');
  });

  console.log('Seeding completed');
  connection.end();
});