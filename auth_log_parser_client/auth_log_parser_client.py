import auth_log_parser

def main():
    if len(sys.argv) < 2 :
        print("Need logs folder argument")
        return
    logs_folder = sys.argv[1]
    for file in os.listdir(logs_folder):
        if file.endswith(".log"):
            with open(os.path.join(logs_folder,file)) as log_file:
                print("Reading file :", log_file.name)
                for log_line in log_file.readlines():
                    print("Parsing line :," sshLog.line)
                    sshLog = parse_line(log_line)
                    if sshLog is not None:
                    	# the log is valid, sshLog is a SSHLog instance

def write_to_csv(fieldnames, values, path_to_csv):
	with open(path_to_csv, "a+") as csv_file:
    	csv_writer = csv.DictWriter(csv_file, delimiter=';', fieldnames=fieldnames)
        csv_writer.writerow(values)


if __name__ == "__main__":
	main()