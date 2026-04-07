const mongoose = require('mongoose');

const fileHistorySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fileName: {
    type: String,
    required: true
  },
  fileType: {
    type: String,
    enum: ['pcap', 'csv', 'log', 'other'],
    default: 'other'
  },
  fileSize: {
    type: Number,
    default: 0
  },
  status: {
    type: String,
    enum: ['uploaded', 'processing', 'completed', 'failed'],
    default: 'uploaded'
  },
  results: {
    totalRequests: { type: Number, default: 0 },
    maliciousRequests: { type: Number, default: 0 },
    attackTypes: { type: Map, of: Number, default: {} },
    mlAccuracy: { type: Number, default: 0 },
    suspiciousIps: { type: [String], default: [] }
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  },
  processedAt: {
    type: Date
  }
});

// Index for quick user lookups
fileHistorySchema.index({ userId: 1, uploadedAt: -1 });

module.exports = mongoose.model('FileHistory', fileHistorySchema);
