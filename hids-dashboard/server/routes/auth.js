const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const OTP = require('../models/OTP');
const TrustedDevice = require('../models/TrustedDevice');
const auth = require('../middleware/auth');

// Email transporter configuration
const createTransporter = () => {
  return nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });
};

// Generate 6-digit OTP
const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

// Generate trusted device token
const generateDeviceToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Send OTP email
const sendOTPEmail = async (email, otp, type) => {
  const transporter = createTransporter();
  
  const subject = type === 'register' 
    ? 'HIDS Dashboard - Verify Your Email' 
    : 'HIDS Dashboard - Login Verification Code';
    
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background: linear-gradient(135deg, #1e3a5f 0%, #0f1c2e 100%); padding: 30px; border-radius: 10px 10px 0 0;">
        <h1 style="color: #fff; margin: 0; font-size: 24px;">HIDS Dashboard</h1>
      </div>
      <div style="background: #fff; padding: 30px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">${type === 'register' ? 'Verify Your Email' : 'Login Verification'}</h2>
        <p style="color: #666; font-size: 16px; line-height: 1.6;">
          ${type === 'register' 
            ? 'Thank you for signing up for HIDS Dashboard. Please use the verification code below to complete your registration:' 
            : 'Use the verification code below to complete your login:'}
        </p>
        <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #1e3a5f;">${otp}</span>
        </div>
        <p style="color: #999; font-size: 14px;">
          This code will expire in 10 minutes. If you didn't request this code, please ignore this email.
        </p>
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
        <p style="color: #999; font-size: 12px; margin: 0;">
          This is an automated message from HIDS Dashboard. Please do not reply to this email.
        </p>
      </div>
    </div>
  `;

  await transporter.sendMail({
    from: `"HIDS Dashboard" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: subject,
    html: htmlContent
  });
};

// Send OTP endpoint
router.post('/send-otp', async (req, res) => {
  try {
    const { email, username, type = 'register' } = req.body;

    if (!email) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email is required'
      });
    }

    // For registration, check if user already exists
    if (type === 'register') {
      const existingUser = await User.findOne({
        $or: [{ email }, ...(username ? [{ username }] : [])]
      });

      if (existingUser) {
        return res.status(400).json({
          error: 'User exists',
          message: existingUser.email === email
            ? 'Email already registered'
            : 'Username already taken'
        });
      }
    }

    // For login, check if user exists
    if (type === 'login') {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'No account found with this email'
        });
      }
    }

    // Delete any existing OTP for this email and type
    await OTP.deleteMany({ email, type });

    // Generate new OTP
    const otp = generateOTP();

    // Store OTP with pending registration data
    const otpDoc = new OTP({
      email,
      otp,
      type,
      pendingData: type === 'register' ? { username } : undefined
    });
    await otpDoc.save();

    // Send OTP via email
    await sendOTPEmail(email, otp, type);

    res.json({
      message: 'Verification code sent to your email',
      email: email.replace(/(.{2})(.*)(@.*)/, '$1***$3') // Partially mask email
    });

  } catch (error) {
    console.error('Send OTP error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to send verification code. Please try again.'
    });
  }
});

// Login verify endpoint - verifies password and checks trusted device
router.post('/login-verify', async (req, res) => {
  try {
    const { email, password, trustedDeviceToken } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email and password are required'
      });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid email or password'
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid email or password'
      });
    }

    // Check if device is trusted
    if (trustedDeviceToken) {
      const trustedDevice = await TrustedDevice.findOne({
        userId: user._id,
        deviceToken: trustedDeviceToken,
        expiresAt: { $gt: new Date() }
      });

      if (trustedDevice) {
        // Device is trusted, skip OTP and login directly
        const token = jwt.sign(
          { id: user._id, email: user.email, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '7d' }
        );

        return res.json({
          message: 'Login successful',
          skipOtp: true,
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email,
            role: user.role
          }
        });
      }
    }

    // Device not trusted, require OTP
    res.json({
      message: 'Password verified. OTP required.',
      skipOtp: false,
      requireOtp: true
    });

  } catch (error) {
    console.error('Login verify error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Login verification failed. Please try again.'
    });
  }
});

// Verify OTP endpoint
router.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp, username, password, type = 'register', trustDevice = false } = req.body;

    if (!email || !otp) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Email and verification code are required'
      });
    }

    // Find OTP record
    const otpRecord = await OTP.findOne({ email, type });

    if (!otpRecord) {
      return res.status(400).json({
        error: 'Invalid Code',
        message: 'Verification code has expired. Please request a new one.'
      });
    }

    // Check attempts
    if (otpRecord.attempts >= 5) {
      await OTP.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        error: 'Too Many Attempts',
        message: 'Too many failed attempts. Please request a new code.'
      });
    }

    // Verify OTP
    if (otpRecord.otp !== otp) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({
        error: 'Invalid Code',
        message: `Invalid verification code. ${5 - otpRecord.attempts} attempts remaining.`
      });
    }

    let user;
    let token;
    let trustedDeviceToken = null;

    if (type === 'register') {
      // Validate registration data
      if (!username || !password) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Username and password are required for registration'
        });
      }

      // Create new user
      user = new User({
        username: username || otpRecord.pendingData?.username,
        email,
        password
      });
      await user.save();

    } else {
      // Login - find existing user
      user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'User not found'
        });
      }
    }

    // Generate JWT token
    token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // If user wants to trust this device, create a trusted device token
    if (trustDevice) {
      trustedDeviceToken = generateDeviceToken();
      
      const trustedDevice = new TrustedDevice({
        userId: user._id,
        deviceToken: trustedDeviceToken,
        userAgent: req.headers['user-agent'],
        ipAddress: req.ip || req.connection.remoteAddress
      });
      await trustedDevice.save();
    }

    // Delete used OTP
    await OTP.deleteOne({ _id: otpRecord._id });

    res.json({
      message: type === 'register' ? 'Registration successful' : 'Login successful',
      token,
      trustedDeviceToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Verification failed. Please try again.'
    });
  }
});

// Register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Please provide username, email, and password'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'User exists',
        message: existingUser.email === email
          ? 'Email already registered'
          : 'Username already taken'
      });
    }

    // Create user
    const user = new User({ username, email, password });
    await user.save();

    // Generate token (7 days expiry)
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to register user'
    });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Please provide email and password'
      });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid email or password'
      });
    }

    // Compare password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid email or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to login'
    });
  }
});

// Get current user
router.get('/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'User not found'
      });
    }

    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      theme: user.theme,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to get user data'
    });
  }
});

module.exports = router;
