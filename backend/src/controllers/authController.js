const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
const { User } = require("../models");
// const CryptoJS = require('crypto-js');
const AES = require("crypto-js/aes");
const Utf8 = require("crypto-js/enc-utf8");

// const SECRET_KEY = process.env.SECRET_KEY
const SECRET_KEY = String(
  process.env.SECRET_KEY || "my-sample-secret-key-123",
).trim();
console.log('Key length:', SECRET_KEY.length);
// Generate JWT Token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  });
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res) => {
  try {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: "Validation error",
        errors: errors.array(),
      });
    }

    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    // Create user
    const user = await User.create({
      name,
      email,
      password,
    });

    // Generate token
    const token = generateToken(user.id);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      data: {
        user: user.toJSON(),
        token,
      },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      message: "Error registering user",
      error: error.message,
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
// exports.login = async (req, res) => {
//   try {
//     // Check validation errors
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       return res.status(400).json({
//         success: false,
//         message: 'Validation error',
//         errors: errors.array()
//       });
//     }

//     const { email, password } = req.body;

//     // Find user by email
//     const user = await User.findOne({ where: { email } });
//     if (!user) {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid credentials'
//       });
//     }

//     // Check password
//     const isMatch = await user.comparePassword(password);
//     if (!isMatch) {
//       return res.status(401).json({
//         success: false,
//         message: 'Invalid credentials'
//       });
//     }

//     // Generate token
//     const token = generateToken(user.id);

//     res.json({
//       success: true,
//       message: 'Login successful',
//       data: {
//         user: user.toJSON(),
//         token
//       }
//     });
//   } catch (error) {
//     console.error('Login error:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error logging in',
//       error: error.message
//     });
//   }
// };
exports.login = async (req, res) => {
  try {
    // 1. Decrypt the incoming payload first
    if (!req.body.payload) {
      return res.status(400).json({
        success: false,
        message: "Encrypted payload is missing",
      });
    }

    let email, password;
    try {
      console.log("Backend SECRET_KEY:", SECRET_KEY);
      // const bytes = CryptoJS.AES.decrypt(req.body.payload, SECRET_KEY);
      // const decryptedText = bytes.toString(CryptoJS.enc.Utf8);
      const bytes = AES.decrypt(req.body.payload, SECRET_KEY);
      const decryptedText = bytes.toString(Utf8);
      const decryptedData = JSON.parse(decryptedText);

      email = decryptedData.email?.trim().toLowerCase();
      password = decryptedData.password;
    } catch (decryptErr) {
      return res.status(400).json({
        success: false,
        message: "Failed to decrypt credentials",
      });
    }

    // 2. Basic manual validation (replaces express-validator on encrypted body)
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // 3. Find user by email (Your existing code)
    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 4. Check password with bcrypt via your model method (Your existing code)
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 5. Generate token (Your existing code)
    const token = generateToken(user.id);

    res.json({
      success: true,
      message: "Login successful",
      data: {
        user: user.toJSON(),
        token,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Error logging in",
      error: error.message,
    });
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: req.user.toJSON(),
      },
    });
  } catch (error) {
    console.error("Get me error:", error);
    res.status(500).json({
      success: false,
      message: "Error fetching user",
      error: error.message,
    });
  }
};

// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
exports.updateProfile = async (req, res) => {
  try {
    const { name, email } = req.body;
    const user = req.user;

    if (name) user.name = name;
    if (email) user.email = email;

    await user.save();

    res.json({
      success: true,
      message: "Profile updated successfully",
      data: {
        user: user.toJSON(),
      },
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({
      success: false,
      message: "Error updating profile",
      error: error.message,
    });
  }
};
