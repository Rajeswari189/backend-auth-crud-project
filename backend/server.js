require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// DB Connection
mongoose.connect("mongodb://127.0.0.1:27017/api_based");

// Models
const User = mongoose.model("User", new mongoose.Schema({
  email: String,
  password: String,
  role: { type: String, default: "user" }
}));

const Task = mongoose.model("Task", new mongoose.Schema({
  title: String,
  userId: String
}));

// Register
app.post("/api/v1/register", async (req, res) => {
  const hashed = await bcrypt.hash(req.body.password, 10);
  await User.create({ email: req.body.email, password: hashed });
  res.json({ message: "User registered" });
});

// Login
app.post("/api/v1/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(401).json({ message: "Invalid user" });

  const valid = await bcrypt.compare(req.body.password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid password" });

  const token = jwt.sign({ id: user._id }, "secret");
  res.json({ token });
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  req.user = jwt.verify(token, "secret");
  next();
}

// Create Task
app.post("/api/v1/tasks", auth, async (req, res) => {
  const task = await Task.create({ title: req.body.title, userId: req.user.id });
  res.json(task);
});

// Get Tasks
app.get("/api/v1/tasks", auth, async (req, res) => {
  const tasks = await Task.find({ userId: req.user.id });
  res.json(tasks);
});

app.listen(5000, () => console.log("Server running on port 5000"));
