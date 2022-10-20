import argparse
import yaml
from yaml.loader import SafeLoader

from secrep.reporting import generate_summary_report, generate_detailed_report

def init_args():
    parser = argparse.ArgumentParser(description='Arguments being passed to the program')
    parser.add_argument('--summarize', '-Z', type=str, required=False, help='Generate a summary report for all vulnerabilities for each OSS from a config file')
    parser.add_argument('--render', '-r', type=str, required=False, help='Generate a detailed report of OSS vulnerabilities from a config file')
    return parser.parse_args()

def read_file(filepath):
    # Open the file and load the file
    with open(filepath) as f:
        config = yaml.load(f, Loader=SafeLoader)
    return config

def run():
    args = init_args()

    if args.summarize:
        config = read_file(args.summarize)
        generate_summary_report(config)
    elif args.render:
        config = read_file(args.render)
        generate_detailed_report(config)

if __name__ == '__main__':
    run()
