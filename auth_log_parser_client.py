import auth_log_parser
import auth_log_enrichment
import sys
import os
import csv
import argparse
import logging as log


def is_dir(dirname):
    """ Checks if a path is an actual directory """
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname


def main():

    parser = argparse.ArgumentParser(description='SSH Log parser')
    parser.add_argument("logs_folder", type=is_dir, help="logs folder")
    parser.add_argument("-v", "--verbose", action="store_true",
                        dest='verbose', help="enable verbosity")
    parser.add_argument("-e", "--enrich", action="store_true",
                        dest='enrich', help="enrich the logs")
    args = parser.parse_args()

    # TODO : global verbose management
    # https://stackoverflow.com/questions/5980042/how-to-implement-the-verbose-or-v-option-into-a-script
    # https://github.com/pypa/virtualenv/blob/4b707b87d43e7e0a945ad831e6ce483b45440149/virtualenv.py#L649-L655
    if(args.verbose):
        print("verbose mode activated.")
    for filename in os.listdir(args.logs_folder):
        filepath = os.path.join(args.logs_folder, filename)
        file_logs = auth_log_parser.parse_file(filepath, args.verbose)
        if(args.enrich):
            auth_log_enrichment.enrich_logs(file_logs, args.verbose)
            # next ? do things with the file_logs ¯\_(ツ)_/¯


def init_csv(fieldnames, path_to_csv):
    with open(path_to_csv, "w+") as csv_file:
        csv_writer = csv.DictWriter(
            csv_file, delimiter=',', fieldnames=fieldnames)
        csv_writer.writeheader()


def write_to_csv(fieldnames, values, path_to_csv):
    with open(path_to_csv, "a+") as csv_file:
        csv_writer = csv.DictWriter(
            csv_file, delimiter=',', fieldnames=fieldnames)
        csv_writer.writerow(values)

if __name__ == "__main__":
    main()
