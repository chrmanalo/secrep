import argparse

def init_args():
    parser = argparse.ArgumentParser(description='Arguments being passed to the program')
    parser.add_argument('--summarize', '-Z', action='store_true', required=False, help='Generate a summary report for all vulnerabilities for each OSS')
    parser.add_argument('--config', '-f', type=str, required=True, help='A config file is required')
    return parser.parse_args()

def run():
    args = init_args()

if __name__ == '__main__':
    run()