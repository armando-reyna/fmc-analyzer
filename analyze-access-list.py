
from __future__ import print_function
from fireREST import FireREST
import json

########################################## CONSTANTS ##########################################
log_file_path = 'access-list-FP-FTD2140-PRI.log'
duplicates_file_path = 'access-list-FP-FTD2140-PRI.duplicates.log'
result_file_path = 'access-list-FP-FTD2140-PRI.result.txt'
error_file_path = 'access-list-FP-FTD2140-PRI.error.log'

device = '10.200.64.6'
username = 'ST00039'
password = 'fpXTHeCtPL67'
domain = 'Global'

parent_prefix = 'access-list'
child_prefix = '  access-list'
init_evaluator = 'advanced'
end_evaluator = 'rule-id'
host_evaluator = 'host'
ifc_evaluator = 'ifc'
########################################## CONSTANTS ##########################################

log_file = None
duplicates_file = None
result_file = None
error_file = None

def print_json(json_object):
    print(json.dumps(json_object.json(), indent=1))

def pretty_json(json_object):
    return json.dumps(json_object.json(), indent=1)

# Initialize a new api object
api = FireREST(hostname=device, username=username, password=password)

domain_id = api.get_domain_id(domain)

# Parent: Blocked-IPs-Security-Requested-FTDMig : 00505697-2F31-0ed3-0000-008590003520
# Child: Blocked-IPs-Security-Requested_split_1 : 00505697-2F31-0ed3-0000-008589941259
# Child: Blocked-IPs-Security-Requested_split_2-FTDMig: 00505697-2F31-0ed3-0000-008590003460

def main():
    lines = log_file.readlines()
    line_count = 0
    object_group = ''
    dictionary = dict()

    for line in lines:
        line_count+=1

        parent = line.startswith(parent_prefix)
        child = line.startswith(child_prefix)

        if parent:
            object_group = ''
            parents = line.split(" ")
            # print(parents)
            index = 0
            for parent in parents :
                if parent == 'object-group':
                    object_group = parents[index+1]
                index+=1
            dictionary = dict()
        elif child:
            # print('evaluating line {}'.format(line_count))
            if object_group == '' :
                line = "(ERR)[No object-group in parent]" + line
                # print(line)
                error_file.write(line)
            else :

                # line = line.strip()
                chunked_line = line.split(" ")
                # line = "  "
                eval_line = ""
                evaluate = False
                evaluated = False

                host = None

                line_chunk_no = 0
                for line_aux in chunked_line :

                    if line_aux.startswith(end_evaluator) :
                        evaluate = False

                    if evaluate :
                        eval_line += line_aux + " "

                    if line_aux == init_evaluator:
                        evaluate = True
                        evaluated = True

                    if line_aux ==  host_evaluator:
                        host = chunked_line[line_chunk_no+1]

                    if host is None and line_aux ==  ifc_evaluator:
                        host = chunked_line[line_chunk_no+2] + ' ' + chunked_line[line_chunk_no+3]

                    line_chunk_no +=1

                if not evaluated :
                    line = "(ERR)[No evaluator " + init_evaluator + "]" + line
                    # print(line)
                    error_file.write(line)
                elif host is None:
                    line = "(ERR)[No host or ifc]" + line
                    # print(line)
                    error_file.write(line)
                elif not eval_line == '':
                    # All logic for duplicates
                    if dictionary.get(eval_line) is not None :
                        print('Duplicate found on line {}'.format(line_count))
                        line_no = dictionary.get(eval_line)
                        lineNo = "{},{}".format(line_no, line_count)
                        dictionary[eval_line] = "{}".format(lineNo)
                        result_file.write("Duplicated lines: {}\n".format(lineNo))
                        result_file.write(line)
                        result_file.write("object-group: \t\t{}\n".format(object_group))
                        immediate_object_group = api.get_immediate_parent(object_group, host)
                        result_file.write("immediate object-group: \t{}\n".format(immediate_object_group))
                        result_file.write("\n"*2)
                    else:
                        # print('Adding line {} to dictionary'.format(line_count))
                        dictionary[eval_line] = "{}".format(line_count)
                else :
                    line = "(ERR)[Nothing to evaluate " + init_evaluator + "]" + line
                    # print(line)
                    error_file.write(line)
        # else:
            # print('line {} not a parent or child'.format(line_count))

        # for key in dictionary:
        #     print('{} {}'.format(key, dictionary[key]))

        duplicates_file.write(line)


print("-" * 85)
print("Domain: " + domain_id)
print("-" * 85)

objects = api.get_system_version()
for object in objects:
    print("Server Version")
    print_json(object)
print("-" * 85)

log_file = open(log_file_path, 'r')
duplicates_file = open(duplicates_file_path, "w")
result_file = open(result_file_path, "w")
error_file = open(error_file_path, "w")

main()

duplicates_file.close()
result_file.close()
error_file.close()