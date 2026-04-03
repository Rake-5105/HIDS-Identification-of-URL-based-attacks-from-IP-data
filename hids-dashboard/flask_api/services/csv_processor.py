import pandas as pd

def process_csv_file(filepath):
    """
    Process CSV file - validate and map columns

    Args:
        filepath: Path to uploaded CSV file

    Returns:
        dict: Processing results with row counts and validation status
    """
    try:
        # Read CSV
        df = pd.read_csv(filepath)

        # Expected columns for detection results
        required_columns = ['timestamp', 'source_ip', 'url', 'classification']

        # Validate columns
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            return {
                'file_type': 'csv',
                'total_rows': len(df),
                'valid': False,
                'message': f'Missing required columns: {", ".join(missing_columns)}',
                'columns': list(df.columns)
            }

        return {
            'file_type': 'csv',
            'total_rows': len(df),
            'valid': True,
            'columns': list(df.columns),
            'message': 'CSV file validated successfully'
        }

    except Exception as e:
        raise Exception(f'CSV processing failed: {str(e)}')
