import argparse
import yaml
from yaml.loader import SafeLoader

from secrep.reporting import generate_summary_report

def init_args():
    parser = argparse.ArgumentParser(description='Arguments being passed to the program')
    parser.add_argument('--summarize', '-Z', type=str, required=False, help='Generate a summary report for all vulnerabilities for each OSS')
    return parser.parse_args()

def run():
    args = init_args()

    if args.summarize:
        # Open the file and load the file
        with open(args.summarize) as f:
            config = yaml.load(f, Loader=SafeLoader)
        generate_summary_report(config)

if __name__ == '__main__':
    run()