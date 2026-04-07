const mongoose = require('mongoose');

// Individual request record for detailed display
const requestDetailSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  source_ip: { type: String, default: '0.0.0.0' },
  url: { type: String, required: true },
  classification: { type: String, default: 'unknown' },
  confidence: { type: Number, default: 90 },
  detection_method: { type: String, default: 'ML' }
}, { _id: false });

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
  // Store individual request details for the Requests page
  detailedRequests: {
    type: [requestDetailSchema],
    default: []
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
