from data_modules.classification import run_hybrid_detection


if __name__ == "__main__":
    summary = run_hybrid_detection(
        input_csv="output/url_feature_dataset.csv",
        output_dir="output",
    )

    print("MODULE 4 - HYBRID DETECTION SUMMARY")
    print(f"  rows: {summary['rows']}")
    print(f"  ml_accuracy: {summary['ml_accuracy']}")
    print(f"  regex_detected: {summary['regex_detected']}")
    print(f"  statistical_suspicious_rows: {summary['statistical_suspicious_rows']}")
    print(f"  output_csv: {summary['output_csv']}")
    print(f"  summary_json: output/module4_summary.json")
