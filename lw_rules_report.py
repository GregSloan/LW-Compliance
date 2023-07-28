from lw_helpers import QueryHelper
import os
from os.path import exists
from datetime import datetime, timedelta, timezone
import json

c_dir = os.path.dirname(__file__)
# Instantiate API helper class
lw_queries = QueryHelper(api_key=os.getenv("LW_API_KEY"),
                         api_secret=os.getenv("LW_API_SECRET"),
                         account=os.getenv("LW_ACCOUNT"))

# Last 24 hours used to timebound searches
current_time = datetime.now(timezone.utc)
start_time = current_time - timedelta(hours=72)
end_time = current_time

# Get hosts to use for tag data
aws_host_inventory = lw_queries.get_inventory(start_time,
                                              end_time,
                                              'AWS',
                                              filters=[{"field": "resourceType",
                                                        "expression": "like",
                                                        "value": "*ec2:instance*"}])
# aws_host_inventory = lw_queries.get_inventory(start_time,
#                                               end_time,
#                                               'AWS'
#                                              )

# Return all vulnerabilities grouped by host
vulnerable_hosts = lw_queries.get_host_vulns(start_time,
                                             end_time,
                                             filters=[{"field": "machineTags.Hostname",
                                                       "expression": "like",
                                                       "value": "ip-10-90*"}])


# merge vulnerability data with host tagging data
# todo: Tag data only available via API for AWS - Azure coming
for host in vulnerable_hosts.values():
    if host['instanceID'] in aws_host_inventory.keys():
        host['tags'] = aws_host_inventory[host['instanceID']]['resourceTags']

# Retrieve all AWS resources for use in tagging compliance data
# todo: Resource data only available via API for AWS - Azure coming
aws_all_resources = lw_queries.get_inventory(start_time, end_time, 'AWS')

# If an aws_accountIds.txt file exists, read in account ID list. Otherwise attempt to get configured accounts via API
aws_config_accounts = []
if exists(c_dir + '/aws_accountIds.txt'):
    with open(c_dir + '/aws_accountIds.txt', 'r') as account_file:
        aws_config_accounts = [line.rstrip() for line in account_file]
if len(aws_config_accounts) == 0:
    aws_config_accounts = lw_queries.get_aws_config_accounts()

# Retrieve latest AWS CIS report grouped by resource for each account
aws_compliance_reports = {}
for account_id in aws_config_accounts:
    aws_compliance_reports[account_id] = lw_queries.get_compliance(account_id, 'AWS_CIS_14')
    aws_compliance_reports[account_id] = lw_queries.get_compliance(account_id, 'LW_AWS_SEC_ADD_1_0',
                                                                   previous_compliance=aws_compliance_reports[account_id])

# merge AWS CIS report data with available resource tagging data
for account_id, aws_compliance in aws_compliance_reports.items():
    for instanceID, resource in aws_compliance.items():
        if resource['Instance ID'] in aws_all_resources.keys():
            if 'resourceTags' in aws_all_resources[resource['Instance ID']].keys():
                resource['tags'] = aws_all_resources[resource['Instance ID']]['resourceTags']

# get lis of configured Azure Tenants and Subscriptions
# azure_config_tenants = lw_queries.get_azure_config_accounts()

# Retrieve latest Azure CIS report grouped by resource for each Tenant/Subsctiption
# azure_compliance_reports = []
# for tenant in azure_config_tenants:
#     new_report = {'tenantId': tenant['tenantId']}
#     for subscription in tenant['subscriptions']:
#         new_report['subscriptionId'] = subscription
#         new_report['report'] = lw_queries.get_azure_compliance(tenant['tenantId'], subscription, 'AZURE_CIS')
#         azure_compliance_reports.append(new_report)

# output all data as json objects and files
now = datetime.now()
prefix = now.strftime('%Y%m%d-%-H%M%S')

for account_id, aws_compliance in aws_compliance_reports.items():
    compliance_filename = "{}_{}_aws_compliance.json".format(prefix, account_id)
    with open('./' + compliance_filename, 'w') as f:
        json.dump(aws_compliance, f)

vuln_filename = "{}_vulnerable_hosts.json".format(prefix)
with open('./' + vuln_filename, 'w') as f:
    json.dump(vulnerable_hosts, f)

print('===================================')
print("Data Export Complete")
print("Compliance Data: {}".format(compliance_filename))
print("Vulnerability Data: {}".format(vuln_filename))
print('===================================')