import argparse
from munch import Munch
import yaml
from yaml.loader import SafeLoader

from secrep.scraping import scrape
from secrep.processing import patch
from secrep.reporting import generate_summary_report, generate_detailed_report

def init_args():
    parser = argparse.ArgumentParser(description='Arguments being passed to the program')
    parser.add_argument('--summarize', '-Z', action='store_true', required=False, help='Generate a summary report for all vulnerabilities for each OSS from a config file')
    parser.add_argument('--scrape', '-s', action='store_true', required=False, help='Start web scraping')
    parser.add_argument('--patch', '-p', action='store_true', required=False, help='Generate mandatory and recommended patch details')
    parser.add_argument('--report', '-r', action='store_true', required=False, help='Generate the detailed report')
    parser.add_argument('--config', '-f', type=str, required=True, help='Config file')
    return parser.parse_args()

def read_file(filepath):
    # Open the file and load the file
    with open(filepath, encoding='utf8') as f:
        # config = yaml.load(f, Loader=SafeLoader)
        config = Munch.fromYAML(f)
    return config

def run():
    args = init_args()
    config = read_file(args.config)
    print(config)
    
    if args.summarize:
        generate_summary_report(config)
        return

    if not (args.scrape or args.patch or args.report):
        scrape(config)
        patch(config)
        generate_detailed_report(config)

    if args.scrape:
        scrape(config)
    if args.patch:
        patch(config)
    if args.report:
        generate_detailed_report(config)

if __name__ == '__main__':
    run()
