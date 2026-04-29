import unittest
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from data_modules.classification.anomaly_detector import score_with_isolation_forest, train_isolation_forest


class IsolationForestAnomalyTests(unittest.TestCase):
    def test_detects_extreme_outlier_row(self):
        rows = []
        for i in range(20):
            rows.append(
                {
                    "url_length": 42 + (i % 3),
                    "special_characters": 4 + (i % 2),
                    "has_sql_keyword": 0,
                    "has_script": 0,
                    "has_traversal": 0,
                }
            )

        rows.append(
            {
                "url_length": 1800,
                "special_characters": 220,
                "has_sql_keyword": 1,
                "has_script": 1,
                "has_traversal": 1,
            }
        )

        df = pd.DataFrame(rows)
        artifacts = train_isolation_forest(df, contamination=0.1, random_state=42)
        anomaly_flag, anomaly_score = score_with_isolation_forest(df, artifacts)

        self.assertEqual(len(anomaly_flag), len(df))
        self.assertEqual(len(anomaly_score), len(df))
        self.assertGreaterEqual(int(anomaly_flag.sum()), 1)
        self.assertEqual(int(anomaly_flag.iloc[-1]), 1)


if __name__ == "__main__":
    unittest.main()