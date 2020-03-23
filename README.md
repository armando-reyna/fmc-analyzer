# FMC Tools
A repository of python scripts to analyze the access list in Cisco FMC and generate results n a txt file

## Requirements
Clone this repo and install the requirements for [fireREST](https://github.com/kaisero/fireREST):
``` bash
git clone https://github.com/rnwolfe/fmc-tools/fmc-tools.git
pip install -r fireREST/requirements.txt
```
Afterwards, you can use the specific tool script you want.

## Configure
Edit the file analyze-access-list.py and configure the constants
- `log_file_path` Input: Is the full path of you input log file for the access list
- `duplicates_file_path` Output: Is the file where all lines will be re written specifying duplicates
- `result_file_path` Output: Is the file where the results will be posted with number of line duplicated and network group 
- `error_file_path` Output: Is the file where all errors will be logged

- `device` Is the ip/host of the FMC API
- `username` Is the username with permissions to the API
- `password` Is the password with permissions to the API
- `domain` Is the domain of the access list

- `parent_prefix` Is the prefix identifier for a parent in the access list
- `child_prefix` Is the prefix identifier for a child in the access list
- `init_evaluator` Is the start regex to identify duplicates in the line 
- `end_evaluator` Is the end regex to identify duplicates in the line

**Note**: If using a child domain, add a `/ ` (note the space after the slash) between parent/child, e.g. `Global/ Child-Domain`. This is due to how the domains are formatted by the FMC

```python
log_file_path = 'input.log'
duplicates_file_path = 'output.duplicates.log'
result_file_path = 'output.result.txt'
error_file_path = 'output.error.log'

device = 'host'
username = 'username'
password = 'password'
domain = 'Global'

parent_prefix = 'access-list'
child_prefix = '  access-list'
init_evaluator = 'advanced'
end_evaluator = 'rule-id'
```

### Execution
```bash
$ python analyze-access-list.py
```