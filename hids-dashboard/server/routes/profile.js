const express = require('express');
const router = express.Router();
const User = require('../models/User');
const FileHistory = require('../models/FileHistory');
const auth = require('../middleware/auth');

// Get user profile
router.get('/', auth, async (req, res) => {
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
      avatar: user.avatar,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to get profile'
    });
  }
});

// Update username
router.put('/username', auth, async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || username.trim().length < 3) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Username must be at least 3 characters'
      });
    }

    // Check if username is taken
    const existingUser = await User.findOne({ 
      username: username.trim(),
      _id: { $ne: req.user.id }
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'Username Taken',
        message: 'This username is already in use'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { username: username.trim(), updatedAt: Date.now() },
      { new: true }
    ).select('-password');

    res.json({
      message: 'Username updated successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Update username error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to update username'
    });
  }
});

// Update password
router.put('/password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Current and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'New password must be at least 6 characters'
      });
    }

    const user = await User.findById(req.user.id);
    
    // Verify current password
    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Current password is incorrect'
      });
    }

    // Update password
    user.password = newPassword;
    await user.save();

    res.json({
      message: 'Password updated successfully'
    });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to update password'
    });
  }
});

// Update theme
router.put('/theme', auth, async (req, res) => {
  try {
    const { theme } = req.body;

    if (!['dark', 'light'].includes(theme)) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Theme must be either "dark" or "light"'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { theme, updatedAt: Date.now() },
      { new: true }
    ).select('-password');

    res.json({
      message: 'Theme updated successfully',
      theme: user.theme
    });
  } catch (error) {
    console.error('Update theme error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to update theme'
    });
  }
});

// Get file history
router.get('/files', auth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const files = await FileHistory.find({ userId: req.user.id })
      .sort({ uploadedAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await FileHistory.countDocuments({ userId: req.user.id });

    res.json({
      files,
      pagination: {
        current: parseInt(page),
        pages: Math.ceil(total / limit),
        total
      }
    });
  } catch (error) {
    console.error('Get file history error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to get file history'
    });
  }
});

// Get user statistics/reports
router.get('/stats', auth, async (req, res) => {
  try {
    const files = await FileHistory.find({ userId: req.user.id });
    
    const stats = {
      totalFiles: files.length,
      totalRequests: 0,
      totalMalicious: 0,
      attackTypes: {},
      recentActivity: []
    };

    files.forEach(file => {
      stats.totalRequests += file.results?.totalRequests || 0;
      stats.totalMalicious += file.results?.maliciousRequests || 0;
      
      if (file.results?.attackTypes) {
        file.results.attackTypes.forEach((count, type) => {
          stats.attackTypes[type] = (stats.attackTypes[type] || 0) + count;
        });
      }
    });

    // Get recent 5 files
    stats.recentActivity = files
      .sort((a, b) => b.uploadedAt - a.uploadedAt)
      .slice(0, 5)
      .map(f => ({
        fileName: f.fileName,
        status: f.status,
        uploadedAt: f.uploadedAt,
        maliciousCount: f.results?.maliciousRequests || 0
      }));

    res.json(stats);
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to get statistics'
    });
  }
});

// Delete account
router.delete('/', auth, async (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Password is required to delete account'
      });
    }

    const user = await User.findById(req.user.id);
    
    // Verify password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        error: 'Authentication Failed',
        message: 'Incorrect password'
      });
    }

    // Delete user's file history
    await FileHistory.deleteMany({ userId: req.user.id });
    
    // Delete user
    await User.findByIdAndDelete(req.user.id);

    res.json({
      message: 'Account deleted successfully'
    });
  } catch (error) {
    console.error('Delete account error:', error);
    res.status(500).json({
      error: 'Server Error',
      message: 'Failed to delete account'
    });
  }
});

module.exports = router;
