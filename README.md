# LW-Compliance
## What it does:
* Generates JSON file of AWS Compliance Report data, grouped by resource, with tags from inventory data when available (those tags include the 'Level' tag that can be used to identify prod vs dev resources)
* Generates JSON file of all Vulnerabilities, grouped by host. For hosts on AWS, tag data is included.

## Limitations (currently):
* Outputs files to the current working directory. These files will be named 
  [current_date/time_stamp]_[accountID]_aws_compliance.json and [current_date/time_stamp]vulnerable_hosts.json.
  There will be a compliance report file for each AWS account configured, and 1 vulnerability report file.
* All results based on most recent compliance report, inventory seen over last 24 hours, and most recent vulnerability assessments
* Credentials must be set as environment variables (see OPERATION)
* If Lacework RBAC is enabled in your tenant, a user (Standard or Service) in the Admin User group is required to run
  without further input. If using a Power user or Read-Only user, an "aws_accountIds.txt" file is necessary

## OPERATION:

### Prerequisites:
* Both attached python files (lw_rules_report.py and lw_helpers.py) in the same directory
* export the following environment variables with valid API key data available in the downloaded JSON from the 
  Lacework tenant: LW_ACCOUNT, LW_API_KEY, LW_API_SECRET
* pip install laceworkcdk
* pip install laceworkreports

### Optional:
* If running using credentials for a non-Admin user, create "aws_accoundIds.txt" in the same directory with one AWS
  account ID per line

### Execution:
`python /path/to/lw_rules_report.py`

# Expected Output:
The script is relatively chatty while operating, printing INFO messages for API calls to stdout.
Completion message with the timestamped file names will be printed.