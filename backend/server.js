const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Blog = require("./models/Blog");
const User = require("./models/User");

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

// ===============================
// MONGODB CONNECTION
// ===============================

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((err) => {
    console.log("MongoDB connection error:", err.message);
  });

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
  res.json({
    message: "Blog API is running"
  });
});

// ===============================
// USER REGISTER
// ===============================

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "All fields are required"
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    res.status(201).json({
      message: "Registration successful"
    });
  } catch (error) {
    res.status(500).json({
      message: "Registration failed",
      error: error.message
    });
  }
});

// ===============================
// USER LOGIN
// ===============================

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatch) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d"
      }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({
      message: "Login failed",
      error: error.message
    });
  }
});

// ===============================
// AUTHENTICATION MIDDLEWARE
// ===============================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      message: "Access denied. Token required"
    });
  }

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Invalid authorization format"
    });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      message: "Invalid or expired token"
    });
  }
}

// ===============================
// GET ALL BLOGS
// Public route
// ===============================

app.get("/api/blogs", async (req, res) => {
  try {
    const blogs = await Blog.find().sort({
      createdAt: -1
    });

    res.json(blogs);
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch blogs",
      error: error.message
    });
  }
});

// ===============================
// GET SINGLE BLOG
// Public route
// ===============================

app.get("/api/blogs/:id", async (req, res) => {
  try {
    const blog = await Blog.findById(req.params.id);

    if (!blog) {
      return res.status(404).json({
        message: "Blog not found"
      });
    }

    res.json(blog);
  } catch (error) {
    res.status(500).json({
      message: "Failed to fetch blog",
      error: error.message
    });
  }
});

// ===============================
// CREATE BLOG
// Login required
// ===============================

app.post(
  "/api/blogs",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        title,
        category,
        content,
        author
      } = req.body;

      if (!title || !category || !content || !author) {
        return res.status(400).json({
          message: "All fields are required"
        });
      }

      const blog = new Blog({
        title,
        category,
        content,
        author
      });

      await blog.save();

      res.status(201).json({
        message: "Blog created successfully",
        blog
      });
    } catch (error) {
      res.status(500).json({
        message: "Failed to create blog",
        error: error.message
      });
    }
  }
);

// ===============================
// UPDATE BLOG
// Login required
// ===============================

app.put(
  "/api/blogs/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const {
        title,
        category,
        content,
        author
      } = req.body;

      const blog = await Blog.findByIdAndUpdate(
        req.params.id,
        {
          title,
          category,
          content,
          author
        },
        {
          new: true,
          runValidators: true
        }
      );

      if (!blog) {
        return res.status(404).json({
          message: "Blog not found"
        });
      }

      res.json({
        message: "Blog updated successfully",
        blog
      });
    } catch (error) {
      res.status(500).json({
        message: "Failed to update blog",
        error: error.message
      });
    }
  }
);

// ===============================
// DELETE BLOG
// Login required
// ===============================

app.delete(
  "/api/blogs/:id",
  authenticateToken,
  async (req, res) => {
    try {
      const blog = await Blog.findByIdAndDelete(
        req.params.id
      );

      if (!blog) {
        return res.status(404).json({
          message: "Blog not found"
        });
      }

      res.json({
        message: "Blog deleted successfully"
      });
    } catch (error) {
      res.status(500).json({
        message: "Failed to delete blog",
        error: error.message
      });
    }
  }
);

// ===============================
// SERVER
// ===============================

const PORT = 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});