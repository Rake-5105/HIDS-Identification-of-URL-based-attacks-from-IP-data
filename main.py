"""
Entry point for the URL-based Attack Identification — Data Collection Module.

Run modes
---------
1. Collect from a specific path:
       python main.py --source /path/to/logs

2. Collect from a PCAP file:
       python main.py --source capture.pcap

3. Collect from an IPDR CSV:
       python main.py --source ipdr_data.csv

4. Use configured default directories (logs/ and pcap_files/):
       python main.py

5. Demonstrate with bundled sample data:
       python main.py --demo
"""

import argparse
import sys
import os

# Ensure the project root is on the path when running directly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data_modules.data_collection import DataCollector, CollectionConfig


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="URL-based Attack Identification — Data Collection Module"
    )
    parser.add_argument(
        "--source", "-s",
        metavar="PATH",
        help="Path to a log file, PCAP file, IPDR CSV, or directory",
        default=None,
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        help="Output directory for results (default: output/)",
        default="output",
    )
    parser.add_argument(
        "--tag", "-t",
        metavar="TAG",
        help="Tag prefix for output filenames",
        default="",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print summary only; do not write output files",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with bundled sample data from sample_data/",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    config = CollectionConfig(
        output_directory=args.output,
        log_level=args.log_level,
    )

    collector = DataCollector(config=config)

    # Determine source
    if args.demo:
        source = os.path.join(os.path.dirname(__file__), "sample_data")
        tag    = args.tag or "demo"
    else:
        source = args.source
        tag    = args.tag

    # Run collection
    result = collector.collect(source=source)
    collector.print_summary(result)

    # Top requestors
    top_ips = collector.top_requestors(result, n=5)
    if top_ips:
        print("Top 5 Requestors (by URL count):")
        for ip, count in top_ips:
            print(f"  {ip:<18}  {count} requests")
        print()

    # Top paths
    top_paths = collector.top_paths(result, n=10)
    if top_paths:
        print("Top 10 URL Paths:")
        for path, count in top_paths:
            print(f"  {count:>6}  {path}")
        print()

    # Save
    if not args.no_save and result.total_records > 0:
        paths = collector.save(result, tag=tag)
        print(f"Results saved to: {config.output_directory}/")
        for k, v in paths.items():
            print(f"  [{k}]  {v}")


if __name__ == "__main__":
    main()
