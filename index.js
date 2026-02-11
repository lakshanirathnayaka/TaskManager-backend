require("dotenv").config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");
const { types } = require("pg");
const jwt = require("jsonwebtoken");
const SECRET_KEY = process.env.SECRET_KEY||5000;


// Fix: Prevent pg from converting DATE columns to JS Date objects (which causes timezone shifts)
types.setTypeParser(1082, (str) => str);

const app = express();
app.use(cors());
app.use(express.json());

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};


// Test route
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

// GET ALL TASKS
app.get("/tasks", authenticateToken, async (req, res) => {
  try {
    const { user_id} = req.user
    const { task_name, task_date } = req.query;
    
    let query = "SELECT * FROM tasks WHERE user_id = $1";
    const values = [user_id];
    
    if (task_name) {
      values.push(`%${task_name}%`);
      query += ` AND task_name ILIKE $${values.length}`;
    }
    
    if (task_date) {
      values.push(task_date);
      query += ` AND task_date = $${values.length}`;
    }
    
    query += " ORDER BY task_date, task_time";

    const result = await pool.query(query, values);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/tasks", authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.user;
    const { task_name, location_name, task_date, task_time, completed } = req.body;

    const existingTask = await pool.query(
      "SELECT * FROM tasks WHERE user_id = $1 AND task_date = $2 AND task_time = $3",
      [user_id, task_date, task_time]
    );

    if (existingTask.rows.length > 0) {
      return res.status(409).json({ error: "You have already scheduled a task same time" });
    }

    const result = await pool.query(
      "INSERT INTO tasks (task_name, location_name, task_date, task_time, user_id, completed) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
      [task_name, location_name, task_date, task_time, user_id, completed || false]
    );

    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE TASK BY ID
app.delete("/tasks/:task_id", authenticateToken, async (req, res) => {
  try {
    const { task_id } = req.params;
    const { user_id } = req.user

    const result = await pool.query(
      "DELETE FROM tasks WHERE task_id = $1 AND user_id = $2 RETURNING *",
      [task_id, user_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.json({
      message: "Task deleted successfully",
      task: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE TASK BY ID
app.put("/tasks/:task_id", authenticateToken, async (req, res) => {
  try {
    const { task_id } = req.params;
    const { user_id } = req.user;
    const { task_name, location_name, task_date, task_time, completed } = req.body;

    const existingTask = await pool.query(
      "SELECT * FROM tasks WHERE user_id = $1 AND task_date = $2 AND task_time = $3",
      [user_id, task_date, task_time]
    );

    // Check for conflict only if time/date changed, or ensure we exclude current task from check
    if (existingTask.rows.length > 0 && existingTask.rows[0].task_id !== parseInt(task_id)) {
      return res.status(409).json({ error: "You have already scheduled a task same time" });
    }

    const result = await pool.query(
      `UPDATE tasks
       SET task_name = $1,
           location_name = $2,
           task_date = $3,
           task_time = $4,
           completed = $5
       WHERE task_id = $6 AND user_id = $7
       RETURNING *`,
      [task_name, location_name, task_date, task_time, completed, task_id, user_id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Task not found" });
    }

    res.json({
      message: "Task updated successfully",
      task: result.rows[0],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { user_name, email, password } = req.body;

    const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (userCheck.rows.length > 0) {
      return res.status(409).json({ error: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await pool.query(
      "INSERT INTO users (user_name, email, password_hash) VALUES ($1, $2, $3) RETURNING *",
      [user_name, email, hashedPassword]
    );

    const user = result.rows[0];
    const token = jwt.sign({ user_id: user.user_id }, SECRET_KEY);
    res.json({ message: "User registered successfully", user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (user.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const token = jwt.sign({ user_id: user.rows[0].user_id }, SECRET_KEY);
    res.json({ message: "Login successful", token, user: { user_id: user.rows[0].user_id, user_name: user.rows[0].user_name } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


// RESET PASSWORD
app.put("/reset-password", async (req, res) => {
  try {
    const { email, new_password } = req.body;

    const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(new_password, salt);

    await pool.query("UPDATE users SET password_hash = $1 WHERE email = $2", [hashedPassword, email]);

    res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
