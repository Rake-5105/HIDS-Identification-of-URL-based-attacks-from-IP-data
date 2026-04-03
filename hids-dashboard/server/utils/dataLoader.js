const fs = require('fs');
const path = require('path');
const csv = require('csv-parser');

const OUTPUT_DIR = path.resolve(process.cwd(), 'output');

// Load module4_summary.json
const loadSummary = () => {
  return new Promise((resolve, reject) => {
    const filePath = path.join(OUTPUT_DIR, 'module4_summary.json');

    if (!fs.existsSync(filePath)) {
      reject(new Error(`Summary file not found at ${filePath}`));
      return;
    }

    try {
      const data = fs.readFileSync(filePath, 'utf8');
      resolve(JSON.parse(data));
    } catch (error) {
      reject(new Error(`Failed to parse summary JSON: ${error.message}`));
    }
  });
};

// Load module4_hybrid_results.csv
const loadRequests = () => {
  return new Promise((resolve, reject) => {
    const filePath = path.join(OUTPUT_DIR, 'module4_hybrid_results.csv');

    if (!fs.existsSync(filePath)) {
      reject(new Error(`Requests file not found at ${filePath}`));
      return;
    }

    const results = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', () => resolve(results))
      .on('error', (error) => reject(new Error(`Failed to parse requests CSV: ${error.message}`)));
  });
};

// Load url_feature_dataset.csv
const loadFeatures = () => {
  return new Promise((resolve, reject) => {
    const filePath = path.join(OUTPUT_DIR, 'url_feature_dataset.csv');

    if (!fs.existsSync(filePath)) {
      reject(new Error(`Features file not found at ${filePath}`));
      return;
    }

    const results = [];
    fs.createReadStream(filePath)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', () => resolve(results))
      .on('error', (error) => reject(new Error(`Failed to parse features CSV: ${error.message}`)));
  });
};

module.exports = {
  loadSummary,
  loadRequests,
  loadFeatures
};
