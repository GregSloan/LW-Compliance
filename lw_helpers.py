from laceworksdk import LaceworkClient
from laceworkreports import common
import re
from laceworkreports.sdk.DataHandlers import (
    DataHandlerTypes,
    ExportHandler,
    QueryHandler,
)
from datetime import datetime

severityMap = {1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low', 5: 'Info'}


def datetime_to_str(adate):
    """

    :type adate: datetime
    """
    return adate.strftime("%Y-%m-%dT%H:%M:%S%z")


class QueryHelper:
    """
    Class to hold all the heavy lifting data operations. Pulling data from the API and processing it
    """

    def __init__(self, api_key, api_secret, account):
        self.api_key = api_key
        self.api_secret = api_secret
        self.account = account
        self.lacework_client = LaceworkClient(api_key=api_key,
                                              api_secret=api_secret,
                                              account=account)

    def __handle_pages(self, generator):
        data = []
        for page in generator:
            data += page['data']
        return data

    def __process_vuln_data(self, vulnerable_hosts):
        hosts = {}
        for host in vulnerable_hosts:
            if host['machineTags']['Hostname'] not in hosts.keys():
                hosts[host['machineTags']['Hostname']] = {"instanceID": host['machineTags']['InstanceId'],
                                                          "Scan_type": "Host Vulnerability",
                                                          "rules": {}}
            if 'vulnId' in host.keys():
                result = 'Failed"'
                if host['status'] in ['Fixed']:
                    result = 'Passed'
                description = 'None available'
                if 'cveProps' in host.keys():
                    if 'description' in host['cveProps'].keys():
                        description = host['cveProps']['description']
                hosts[host['machineTags']['Hostname']]['rules'][host['vulnId']] = {'Severity': host['severity'],
                                                                                   'Scan Result': result,
                                                                                   'Rule description': description}
        return hosts

    def __process_compliance_data(self, compliance_report):
        resources = {}
        all_rules = {}
        for rule in compliance_report['data'][0]['recommendations']:
            if 'VIOLATIONS' in rule.keys():
                for violation in rule['VIOLATIONS']:
                    violation_resource = 'default'
                    if 'resource' in violation.keys():
                        violation_resource = violation['resource']
                    if violation_resource not in resources.keys():
                        resources[violation_resource] = {"Instance ID": violation_resource,
                                                         'rules': {},
                                                         "Scan_type": "Compliance Report"}
                    resources[violation_resource]['rules'][rule['REC_ID']] = {'Severity': severityMap[rule['SEVERITY']],
                                                                              'Recommendation': tuple(
                                                                                  violation['reasons']),
                                                                              'Rule Description': rule['TITLE'],
                                                                              'Scan Result': 'Failed'
                                                                              }
            if 'SUPPRESSIONS' in rule.keys():
                for suppression_resource in rule['SUPPRESSIONS']:
                    if suppression_resource not in resources.keys():
                        resources[suppression_resource] = {"Instance ID": suppression_resource,
                                                           'rules': {},
                                                           'Scan_type': 'Comliance Report'}
                    resources[suppression_resource]['rules'][rule['REC_ID']] = {'Severity': severityMap[rule['SEVERITY']],
                                                                                'Recommendation': 'None',
                                                                                'Rule Description': rule['TITLE'],
                                                                                'Scan Result': 'Suppressed'
                                                                                }

        for resource in resources.values():
            for rule in compliance_report['data'][0]['recommendations']:
                if rule['REC_ID'] not in resource['rules'].keys():
                    resource['rules'][rule['REC_ID']] = {'Severity': severityMap[rule['SEVERITY']],
                                                            'Recommendation': 'None',
                                                            'Rule Description': rule['TITLE'],
                                                            'Scan Result': 'Passed'
                                                            }


        return resources

    def get_azure_config_accounts(self):
        tenants = self.lacework_client.cloud_accounts.get(type='AzureCfg')
        tenant_list = []
        for tenant in tenants['data']:
            tenantid = tenant['data']['tenantId']
            tenant_list.append({'tenantId': tenantid})

        for tenant in tenant_list:
            subscriptions = self.lacework_client.compliance.list_azure_subscriptions(tenant['tenantId'])
            subscription_list = subscriptions['data'][0]['subscriptions']
            tenant['subscriptions'] = []
            for subscription in subscription_list:
                tenant['subscriptions'].append(subscription.split('(')[0].rstrip())

        return tenant_list

    def get_aws_config_accounts(self):
        accounts = self.lacework_client.cloud_accounts.get(type='AwsCfg')
        self.lacework_client
        account_ids = []
        for account in accounts['data']:
            credential = account['data']['crossAccountCredentials']['roleArn']
            account_id = credential.split('::')[1].split(':')[0]
            account_ids.append(account_id)

        return account_ids

    def get_inventory(self, start_time, end_time, dataset, filters=None):
        """

        :type start_time: datetime
        :type end_time: datetime
        :type dataset: str
        :type filters: list of dict
        """
        # dataset is "AwsCompliance"

        ARN_RE = re.compile('.*Arn.*')
        if filters is None:
            filters = []
        start_time = datetime_to_str(start_time)
        end_time = datetime_to_str(end_time)

        # Query
        inventory = self.lacework_client.inventory.search(json={
            "timeFilters": {
                "startTime": start_time,
                "endTime": end_time
            },
            "dataset": dataset,
            "filters": filters,
            "returns": ["cloudDetails", "csp", "resourceConfig", "resourceId", "resourceType", "resourceTags"]
        })

        inventory = self.__handle_pages(inventory)

        resource_dict = {}
        for resource in inventory:
            if 'resourceId' in resource.keys():
                if 'resourceConfig' in resource.keys():
                    if isinstance(resource['resourceConfig'], str):
                        resource_dict[resource['resourceId']] = resource
                    else:
                        arn_config_attribute_list = list(filter(ARN_RE.match, resource['resourceConfig'].keys()))
                        if len(arn_config_attribute_list) == 1:
                            resource_dict[resource['resourceConfig'][arn_config_attribute_list[0]]] = resource
                        elif len(arn_config_attribute_list) > 1:
                            if "subscription" in resource['resourceType']:
                                resource_dict[resource['resourceConfig']['SubscriptionArn']] = resource
                            elif "topic" in resource['resourceType']:
                                resource_dict[resource['resourceConfig']['TopicArn']] = resource
                            elif "loadbalancer" in resource['resourceType']:
                                resource_dict[resource['resourceConfig']['LoadBalancerArn']] = resource
                            else:
                                print('WARNING: Unhandled Resource Type with multiple ARNS in resourceConfig {} {}'.format(resource['resourceType'],
                                                                                                                           tuple(arn_config_attribute_list)))
                        else:
                            svc, resourcetype = resource['resourceType'].split(':')
                            if 'AvailabilityZone' in resource['resourceConfig'].keys():
                                avail_zone = resource['resourceConfig']['AvailabilityZone']
                                arn = "arn:aws:%s:%s:%s/%s".format(svc, avail_zone, resourcetype, resource['resourceId'])
                                resource_dict[arn] = resource
                            else:
                                resource_dict[resource['resourceId']] = resource
                else:
                    resource_dict[resource['resourceId']] = resource
            else:
                # if resource['resourceType'] in resource_dict.keys():
                #     print("duplicate resourceType %s", resource['resourceType'])
                resource_dict[resource['resourceType']] = resource
        return resource_dict

    def get_compliance(self, accountid, report_type):
        """

        :type accountid: str
        :type report_type: str
        """
        compliance = self.lacework_client.reports.get(primary_query_id=accountid, format="json", report_type=report_type)
        #compliance = self.lacework_client.compliance.get_latest_aws_report(accountid,
        #                                                                   file_format="json",
        #                                                                   report_type=report_type)

        return self.__process_compliance_data(compliance)

    def get_azure_compliance(self, tenantid, subscriptionid, report_type):
        """

        :param report_type:  str
        :param subscriptionid: str
        :type tenantid: str
        """
        compliance = self.lacework_client.compliance.get_latest_azure_report(tenantid,
                                                                             subscriptionid,
                                                                             file_format="json",
                                                                             report_type=report_type)
        return self.__process_compliance_data(compliance)

    def get_host_vulns(self, start_time, end_time, filters=None):
        """

        :type start_time: datetime
        :type end_time: datetime
        :type filters: list of dict
        """
        if filters is None:
            filters = []
        vulnerable_hosts = ExportHandler(
            format=DataHandlerTypes.DICT,
            results=QueryHandler(
                client=self.lacework_client,
                type=common.ObjectTypes.Vulnerabilities.value,
                object=common.VulnerabilitiesTypes.Hosts.value,
                start_time=start_time,
                end_time=end_time,
                filters=filters,
                returns=["mid", "cveProps", "severity", "status", "vulnId", "evalCtx", "fixInfo", "featureKey",
                         "machineTags"]
            ).execute()).export()

        return self.__process_vuln_data(vulnerable_hosts)


def main():
    import os
    from datetime import timezone, timedelta
    query_helper = QueryHelper(api_key=os.getenv("LW_API_KEY"),
                               api_secret=os.getenv("LW_API_SECRET"),
                               account=os.getenv("LW_ACCOUNT"))

    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(hours=24)
    end_time = current_time
    tenants = query_helper.get_azure_config_accounts()
    query_helper.get_azure_compliance(start_time, end_time, tenants[0]['tenantId'], tenants[0]['subscriptions'][1],'AZURE_CIS')


if __name__ == "__main__":
    main()
