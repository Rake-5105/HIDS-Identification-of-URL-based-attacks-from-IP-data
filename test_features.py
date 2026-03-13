import pandas as pd
from pathlib import Path
from data_modules.feature_extraction.url_features import extract_features

# Load the latest URL dataset generated earlier.
output_dir = Path("output")
csv_files = sorted(output_dir.glob("demo_url_requests_*.csv"), key=lambda p: p.stat().st_mtime)
if not csv_files:
	raise FileNotFoundError("No demo_url_requests_*.csv files found in output/")

input_file = csv_files[-1]
df = pd.read_csv(input_file)

url_col = "url" if "url" in df.columns else "full_url" if "full_url" in df.columns else None
if url_col is None:
	raise KeyError("Expected 'url' or 'full_url' column in the input CSV")

# Apply feature extraction
features = df[url_col].apply(extract_features)

# Convert features to dataframe columns
features_df = pd.json_normalize(features)

# Combine original data + features
result = pd.concat([df, features_df], axis=1)

print(result.head())

# Save result
result.to_csv("output/url_feature_dataset.csv", index=False)

print("Feature extraction complete. Check output/url_feature_dataset.csv")