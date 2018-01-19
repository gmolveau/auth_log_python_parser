import auth_log_parser
import sys, os, csv

def main():
    if len(sys.argv) < 2 :
        print("Need logs folder argument")
        return
    logs_folder = sys.argv[1]
    for file in os.listdir(logs_folder):
        if file.endswith(".log"):
            with open(os.path.join(logs_folder,file)) as log_file:
                print("Reading file :", log_file.name)
                with open("out.csv", "a+") as csv_file:
                    fieldnames = ["date", "ip", "country", "provider", "tld", "username", "auth_method", "success"]
                    csv_writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
                    csv_writer.writeheader()
                    for log_line in log_file.readlines():
                        sshLog = auth_log_parser.parse_line(log_line)
                        if sshLog is not None:
                            print("Parsing line :", sshLog.line)
                            values = {
                                "date" : sshLog.date['integer'],
                                "ip" : sshLog.source_ip['integer'],
                                "country" : sshLog.whois['country']['integer'],
                                "provider" : sshLog.whois['provider'],
                                "tld" : sshLog.whois['tld'],
                                "username" : sshLog.username,
                                "auth_method" : sshLog.auth_method['integer'],
                                "success" : sshLog.success['integer']
                            }
                            csv_writer.writerow(values)

def write_to_csv(fieldnames, values, path_to_csv, init=False):
    with open(path_to_csv, "a+") as csv_file:
        if init:
            csv_writer.writeheader()
        csv_writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
        csv_writer.writerow(values)


if __name__ == "__main__":
    main()