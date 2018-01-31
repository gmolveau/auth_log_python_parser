import re
import os
import datetime

# TODO : errors checking, more verbose


def parse_line(log_line, verbose=False):
    """ return SSHLog object from a log line """
    # TODO : use the verbose
    m = re.search(r"([A-Za-z]{3}\s+[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2}) (.*) (.*): (Failed|Accepted) (password|publickey|none) for(\s(invalid user)\s|\s)(.*) from (.*) port ([0-9]{1,5}) (.*)", log_line)
    if m is None:
        return

    log = dict()
    log["server_name"] = m.group(2)
    log["process"] = m.group(3)
    log["success"] = m.group(4)
    log["auth_method"] = m.group(5)
    log["source_ip"] = dict()
    log["source_ip"]["text"] = m.group(9)
    log["source_port"] = m.group(10)
    log["invalid_user"] = dict()
    log["invalid_user"]["text"] = "invalid user" if m.group(7) == "invalid user" else "valid user"
    log["invalid_user"]["integer"] = 1 if log["invalid_user"]["text"] == "invalid user" else 0 
    log["user"] = re.sub('[^0-9a-zA-Z_-]+', '', m.group(8))
    log["source_rsa"] = m.group(11)

    # DATE
    log["date"] = dict()
    log["date"]["original"] = m.group(1)
    now = datetime.datetime.now()
    dt = datetime.datetime.strptime(
        str(now.year) + ' ' + log["date"]["original"], '%Y %b %d %H:%M:%S')
    if dt > now:
        dt = dt.replace(year=now.year - 1)
    log["date"]["datetime"] = dt
    log["date"]["text"] = log["date"]["datetime"].strftime("%Y-%m-%d %H:%M:%S")
    log["date"]["year"] = log["date"]["datetime"].year
    log["date"]["month"] = log["date"]["datetime"].month
    log["date"]["day"] = log["date"]["datetime"].day
    log["date"]["hour"] = log["date"]["datetime"].hour
    log["date"]["minute"] = log["date"]["datetime"].minute
    log["date"]["second"] = log["date"]["datetime"].second

    if(verbose):
        print(
            "\n --- LOG --- \n"
            " date:",
            log["date"]["text"],
            "\n",
            "server name:",
            log["server_name"],
            "\n",
            "process:",
            log["process"],
            "\n",
            "success:",
            log["success"],
            "\n",
            "auth method:",
            log["auth_method"],
            "\n",
            "valid? :",
            log["invalid_user"]["text"],
            "\n",
            "user:",
            log["user"],
            "\n",
            "source ip:",
            log["source_ip"]["text"],
            "\n",
            "source port:",
            log["source_port"],
            "\n",
            "rsa certificate? :",
            log["source_rsa"],
            "\n"
        )

    return log


def parse_file(log_file_path, verbose=False):
    # TODO : use the verbose
    if os.path.isfile(log_file_path):
        print(os.path.basename(log_file_path))
        if not os.path.basename(log_file_path).startswith("."):
            if(verbose):
                total_lines = len(open(log_file_path).readlines())
            with open(log_file_path) as log_file:
                if(verbose):
                    print("Reading file :", log_file.name)
                    index_line = 0
                logs = []
                for log_line in log_file.readlines():
                    if(verbose):
                        index_line += 1
                        print("Parsing line :", index_line, "/", total_lines)
                    sshLog = parse_line(log_line, verbose)
                    if sshLog is not None:
                        logs.append(sshLog)
                return logs
        else:
            print(log_file_path, "is a hidden file.")
            return
    else:
        print(log_file_path, "is not a valid file.")
        return
