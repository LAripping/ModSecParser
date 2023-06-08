import json
import sys
import re


def attack_scores(message):
    score_regex ="SQLI=(\d*),XSS=(\d*),RFI=(\d*),LFI=(\d*),RCE=(\d*),PHPI=(\d*),HTTP=(\d*),SESS=(\d*)"
    scores = re.search(score_regex,message).groups()
    # print(scores)
    return {
        "SQLI":int(scores[0]),
        "XSS":int(scores[1]),
        "RFI":int(scores[2]),
        "LFI":int(scores[3]),
        "RCE":int(scores[4]),
        "PHPI":int(scores[5]),
        "HTTP":int(scores[6]),
        "SESS":int(scores[7])
    }  

def usage():
    print("Parse ModSecurity log and show messages where a given attack was detected against a given parameter\n")
    print("Usage: %s <logfile> <param> <ATTACK> [verbose]" % sys.argv[0])
    print("   eg: %s modsec_audit.log pollid  SQLI" % sys.argv[0])
    exit()

def parse_json(log):
    log_dict = {}
    lines = log.splitlines()
    entry = {}
    parsingHeader = False

    for line in lines:
        if line == '': continue
        if line.startswith('--'):
            [id, part] = [x for x in line.split('-') if x != '']
            if(id not in log_dict): log_dict[id] = []
            entry = {'part': part}
            log_dict[id].append(entry)
            parsingHeader = True
            continue
        if parsingHeader:
            entry['header'] = line
            if entry['part'] == 'B':
                headerFields = line.split(' ')
                entry['method'] = headerFields[0]
                entry['path'] = headerFields[1]
            parsingHeader = False
            continue
        (k, _, v) = line.partition(':')
        entry[k] = v
    return log_dict 


if __name__ == "__main__":
    if len(sys.argv)<4:
        usage()

    with open(sys.argv[1], 'r') as f:
        log = f.read()

    log_dict = parse_json(log)
    for k,item in log_dict.items():
        param_found_in_item = False
        
        # first pass, looking for param in C-part
        for part in item:
            if part["part"] == "C":
                if "header" not in part:
                    param_found_in_item = False
                    break
                if sys.argv[2] in part["header"]:
                    param_found_in_item = True
                    break

        if not param_found_in_item:
            continue # move on to next item
        
        # second pass, looking for user-specified attack detected in H-part
        for part in item:
            if part["part"] == "H":
                if "Message" not in part:
                    break
                scores = attack_scores(part["Message"])
                attack_max_score = max(scores, key = lambda k: scores[k])
                if attack_max_score == sys.argv[3]: # bingo
                    header_regex = "\[([0-9a-zA-Z:/]*) --[0-9]*\] [a-zA-Z0-9@]* ([0-9\.]*)"
                    header_groups = re.search(header_regex,item[0]["header"]).groups()
                    outline = "ts:%s src:%s atk:%s par:%s" % (header_groups[0], header_groups[1], sys.argv[3],sys.argv[2]) 
                    if len(sys.argv)>4 and sys.argv[4]=="verbose":
                        outline += " %s" % part["header"]
                    print(outline)
                    break

