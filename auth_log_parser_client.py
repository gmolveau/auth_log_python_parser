import auth_log_parser
import sys, os, csv, argparse
import logging as log

def is_dir(dirname):
    """Checks if a path is an actual directory"""
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

def main():
    
    parser = argparse.ArgumentParser(description='SSH Log parser')
    parser.add_argument("logs_folder", type=is_dir, help="logs folder")
    parser.add_argument("-v", "--verbose", action="store_true", dest='verbose', help="enable verbosity")
    parser.add_argument("--full", action="store_true", dest='full', help="complete SSH Log with whois")
    args = parser.parse_args()

    # verbose management
    if args.verbose:
        log.basicConfig(format="%(levelname)s: %(message)s", level=log.DEBUG)
        log.info("Verbose mode.")
    else:
        log.basicConfig(format="%(levelname)s: %(message)s")

    fieldnames = ["date","ip","country","provider","invalid_user","username","auth_method","success"]
    init_csv(fieldnames ,"good.csv")
    init_csv(fieldnames ,"bad.csv")
    file_logs = auth_log_parser.parse_folder(args.logs_folder, args.full)
    for sshLog in file_logs:
        values = {
            "date" : sshLog.date['integer'],
            "ip" : sshLog.source_ip['text'],
            "country" : sshLog.whois['country']['integer'],
            "provider" : sshLog.whois['provider'],
            "invalid_user": sshLog.invalid_user,
            "username" : sshLog.username,
            "auth_method" : sshLog.auth_method['text'],
            "success" : sshLog.success['text']
        }
        if categorize_log(values):
            write_to_csv(fieldnames, values, "good.csv")
        else:
            write_to_csv(fieldnames, values, "bad.csv")

def categorize_log(log):
    if log['username'] in ['gwendal', 'greg', 'gregoire', 'ronan', 'adrien', 'greygz']:
        return True
    return False if log['success'] == 'Failed' else True

def init_csv(fieldnames, path_to_csv):
    with open(path_to_csv, "w+") as csv_file:
        csv_writer = csv.DictWriter(csv_file, delimiter=',', fieldnames=fieldnames)
        csv_writer.writeheader()

def write_to_csv(fieldnames, values, path_to_csv):
    with open(path_to_csv, "a+") as csv_file:
        csv_writer = csv.DictWriter(csv_file, delimiter=',', fieldnames=fieldnames)
        csv_writer.writerow(values)

if __name__ == "__main__":
    main()