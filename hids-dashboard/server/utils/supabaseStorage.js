const fs = require('fs').promises;
const path = require('path');
const { getSupabase } = require('../config/supabase');

// Bucket names in Supabase Storage
const BUCKETS = {
  UPLOADS: 'uploads',      // Uploaded log/pcap/csv files
  REPORTS: 'reports'        // Analysis reports & results
};

/**
 * Initialize Supabase storage buckets (run once on server start)
 */
const initBuckets = async () => {
  const supabase = getSupabase();
  if (!supabase) return;

  for (const bucket of Object.values(BUCKETS)) {
    const { error } = await supabase.storage.createBucket(bucket, {
      public: false,
      fileSizeLimit: 52428800 // 50MB
    });

    if (error && !error.message.includes('already exists')) {
      console.error(`Failed to create bucket "${bucket}":`, error.message);
    } else {
      console.log(`[Supabase] Bucket "${bucket}" ready`);
    }
  }
};

/**
 * Upload a file to Supabase Storage
 * @param {string} localFilePath - Path to the local file
 * @param {string} bucket - Bucket name ('uploads' or 'reports')
 * @param {string} storagePath - Path inside the bucket (e.g. 'userId/filename.csv')
 * @returns {object} { url, path, error }
 */
const uploadToSupabase = async (localFilePath, bucket, storagePath) => {
  const supabase = getSupabase();
  if (!supabase) {
    return { url: null, path: storagePath, error: 'Supabase not configured' };
  }

  try {
    const fileBuffer = await fs.readFile(localFilePath);
    const ext = path.extname(localFilePath).toLowerCase();

    // Determine content type
    const contentTypes = {
      '.csv': 'text/csv',
      '.log': 'text/plain',
      '.txt': 'text/plain',
      '.pcap': 'application/octet-stream',
      '.pcapng': 'application/octet-stream',
      '.json': 'application/json',
      '.pdf': 'application/pdf'
    };

    const { data, error } = await supabase.storage
      .from(bucket)
      .upload(storagePath, fileBuffer, {
        contentType: contentTypes[ext] || 'application/octet-stream',
        upsert: true
      });

    if (error) throw error;

    // Get a signed URL valid for 7 days
    const { data: urlData } = await supabase.storage
      .from(bucket)
      .createSignedUrl(storagePath, 7 * 24 * 60 * 60);

    return {
      url: urlData?.signedUrl || null,
      path: data.path,
      error: null
    };
  } catch (error) {
    console.error('Supabase upload error:', error.message);
    return { url: null, path: storagePath, error: error.message };
  }
};

/**
 * Save analysis report/results JSON to Supabase
 * @param {string} userId - User ID
 * @param {string} uploadId - Upload job ID
 * @param {object} results - Analysis results object
 * @returns {object} { url, path, error }
 */
const saveReport = async (userId, uploadId, results) => {
  const supabase = getSupabase();
  if (!supabase) {
    return { url: null, path: null, error: 'Supabase not configured' };
  }

  try {
    const reportPath = `${userId}/${uploadId}/report.json`;
    const reportData = JSON.stringify(results, null, 2);

    const { data, error } = await supabase.storage
      .from(BUCKETS.REPORTS)
      .upload(reportPath, Buffer.from(reportData), {
        contentType: 'application/json',
        upsert: true
      });

    if (error) throw error;

    const { data: urlData } = await supabase.storage
      .from(BUCKETS.REPORTS)
      .createSignedUrl(reportPath, 7 * 24 * 60 * 60);

    return {
      url: urlData?.signedUrl || null,
      path: data.path,
      error: null
    };
  } catch (error) {
    console.error('Supabase report save error:', error.message);
    return { url: null, path: null, error: error.message };
  }
};

/**
 * List all files for a user in a bucket
 * @param {string} userId - User ID
 * @param {string} bucket - Bucket name
 * @returns {array} List of files
 */
const listUserFiles = async (userId, bucket) => {
  const supabase = getSupabase();
  if (!supabase) return [];

  try {
    const { data, error } = await supabase.storage
      .from(bucket)
      .list(userId, {
        limit: 100,
        sortBy: { column: 'created_at', order: 'desc' }
      });

    if (error) throw error;
    return data || [];
  } catch (error) {
    console.error('Supabase list error:', error.message);
    return [];
  }
};

/**
 * Get a download URL for a file
 * @param {string} bucket - Bucket name
 * @param {string} filePath - Path inside bucket
 * @returns {string|null} Signed download URL
 */
const getDownloadUrl = async (bucket, filePath) => {
  const supabase = getSupabase();
  if (!supabase) return null;

  try {
    const { data, error } = await supabase.storage
      .from(bucket)
      .createSignedUrl(filePath, 3600); // 1 hour

    if (error) throw error;
    return data?.signedUrl || null;
  } catch (error) {
    console.error('Supabase download URL error:', error.message);
    return null;
  }
};

module.exports = {
  BUCKETS,
  initBuckets,
  uploadToSupabase,
  saveReport,
  listUserFiles,
  getDownloadUrl
};
