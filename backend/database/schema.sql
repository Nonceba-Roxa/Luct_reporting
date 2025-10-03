
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('student', 'lecturer', 'prl', 'pl') NOT NULL,
  stream VARCHAR(255)
);

CREATE TABLE courses (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  code VARCHAR(255) NOT NULL,
  stream VARCHAR(255) NOT NULL,
  description TEXT
);

CREATE TABLE classes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  course_id INT,
  lecturer_id INT,
  venue VARCHAR(255),
  scheduled_time VARCHAR(255),
  total_students INT,
  stream VARCHAR(255),
  FOREIGN KEY (course_id) REFERENCES courses(id),
  FOREIGN KEY (lecturer_id) REFERENCES users(id)
);

CREATE TABLE reports (
  id INT AUTO_INCREMENT PRIMARY KEY,
  lecturer_id INT,
  class_id INT,
  week INT,
  date DATE,
  topic VARCHAR(255),
  learning_outcomes TEXT,
  present_students INT,
  total_students INT,
  venue VARCHAR(255),
  scheduled_time VARCHAR(255),
  recommendations TEXT,
  prl_feedback TEXT,
  status ENUM('pending', 'reviewed') DEFAULT 'pending',
  FOREIGN KEY (lecturer_id) REFERENCES users(id),
  FOREIGN KEY (class_id) REFERENCES classes(id)
);

CREATE TABLE ratings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rater_id INT,
  ratee_id INT NULL,
  rating INT,
  comment TEXT,
  type ENUM('student_to_lecturer', 'lecturer_to_facilities', 'prl_to_lecturer'),
  FOREIGN KEY (rater_id) REFERENCES users(id)
);