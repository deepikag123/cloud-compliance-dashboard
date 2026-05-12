import boto3
import json
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init
from tabulate import tabulate

# Initialize colorama for colored output on Windows
init(autoreset=True)

# Connect to AWS using your configured credentials
# boto3 automatically reads from ~/.aws/credentials (set by aws configure)
session = boto3.Session(region_name='ap-south-1')

# Create AWS service clients
# A "client" is like a connection/handle to a specific AWS service
ec2_client = session.client('ec2')
s3_client = session.client('s3')
iam_client = session.client('iam')
cloudtrail_client = session.client('cloudtrail')

# This list will store all our findings
findings = []
remediation_count = 0
total_resources = 0

print(Fore.CYAN + "=" * 70)
print(Fore.CYAN + "  CLOUD COMPLIANCE & SECURITY MONITORING - ISO 27001 AUDIT")
print(Fore.CYAN + "=" * 70)
print(f"\nAudit started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

# ============================================================
# CHECK 1: EC2 Security Groups - SSH open to the world
# ============================================================
# ISO 27001 Control: A.9.4 - Access control to systems and applications
# CIS Benchmark: 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
print(Fore.YELLOW + "\n[CHECK 1] Scanning EC2 Security Groups for open SSH access...")

# get_paginator handles large results by fetching page by page
# describe_security_groups returns all security groups in your account
paginator = ec2_client.get_paginator('describe_security_groups')
pages = paginator.paginate()

for page in pages:
    for sg in page['SecurityGroups']:
        total_resources += 1
        sg_id = sg['GroupId']
        sg_name = sg.get('GroupName', 'Unknown')
        
        for rule in sg.get('IpPermissions', []):
            # Check if port 22 (SSH) is open
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 0)
            
            for ip_range in rule.get('IpRanges', []):
                # 0.0.0.0/0 means "open to the entire internet" — critical risk
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if from_port <= 22 <= to_port:
                        print(Fore.RED + f"  ❌ CRITICAL: Security Group {sg_id} ({sg_name}) allows SSH from 0.0.0.0/0")
                        findings.append({
                            'Severity': 'CRITICAL',
                            'Resource Type': 'EC2 Security Group',
                            'Resource ID': sg_id,
                            'Resource Name': sg_name,
                            'Finding': 'SSH port 22 open to entire internet (0.0.0.0/0)',
                            'ISO 27001 Control': 'A.9.4 - System Access Control',
                            'Remediation': 'Restrict SSH to specific IP ranges or use AWS Systems Manager Session Manager',
                            'Status': 'NON-COMPLIANT'
                        })
                        remediation_count += 1

print(Fore.GREEN + "  ✅ Security Group scan complete")

# ============================================================
# CHECK 2: S3 Bucket Public Access
# ============================================================
# ISO 27001 Control: A.8.2 - Information Classification
# Public S3 buckets can expose sensitive data to the internet
print(Fore.YELLOW + "\n[CHECK 2] Scanning S3 Buckets for public access...")

response = s3_client.list_buckets()
buckets = response['Buckets']

for bucket in buckets:
    total_resources += 1
    bucket_name = bucket['Name']
    
    try:
        # Check public access block settings
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        config = pab['PublicAccessBlockConfiguration']
        
        # All four settings must be True for a bucket to be fully private
        if not all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ]):
            print(Fore.RED + f"  ❌ HIGH: S3 Bucket '{bucket_name}' has public access enabled!")
            findings.append({
                'Severity': 'HIGH',
                'Resource Type': 'S3 Bucket',
                'Resource ID': bucket_name,
                'Resource Name': bucket_name,
                'Finding': 'S3 bucket does not block all public access',
                'ISO 27001 Control': 'A.8.2 - Information Classification & Handling',
                'Remediation': 'Enable Block All Public Access in S3 bucket settings',
                'Status': 'NON-COMPLIANT'
            })
            remediation_count += 1
        else:
            print(Fore.GREEN + f"  ✅ S3 Bucket '{bucket_name}' — public access blocked")
            findings.append({
                'Severity': 'INFO',
                'Resource Type': 'S3 Bucket',
                'Resource ID': bucket_name,
                'Resource Name': bucket_name,
                'Finding': 'Public access is properly blocked',
                'ISO 27001 Control': 'A.8.2',
                'Remediation': 'None required',
                'Status': 'COMPLIANT'
            })
    
    except Exception as e:
        print(Fore.YELLOW + f"  ⚠️  Could not check bucket '{bucket_name}': {str(e)}")

# ============================================================
# CHECK 3: IAM Root Account Access Keys
# ============================================================
# ISO 27001 Control: A.9.2 - User access management
# Root account should never have active access keys — extreme security risk
print(Fore.YELLOW + "\n[CHECK 3] Checking IAM Root Account Access Keys...")

# get_account_summary returns high-level IAM info including root key status
summary = iam_client.get_account_summary()
account_summary = summary['SummaryMap']
total_resources += 1

if account_summary.get('AccountAccessKeysPresent', 0) > 0:
    print(Fore.RED + "  ❌ CRITICAL: Root account has active access keys!")
    findings.append({
        'Severity': 'CRITICAL',
        'Resource Type': 'IAM Root Account',
        'Resource ID': 'root',
        'Resource Name': 'AWS Root Account',
        'Finding': 'Active access keys found on root account',
        'ISO 27001 Control': 'A.9.2 - User Access Management',
        'Remediation': 'Delete root access keys immediately. Use IAM users instead.',
        'Status': 'NON-COMPLIANT'
    })
    remediation_count += 1
else:
    print(Fore.GREEN + "  ✅ Root account has no active access keys — COMPLIANT")
    findings.append({
        'Severity': 'INFO',
        'Resource Type': 'IAM Root Account',
        'Resource ID': 'root',
        'Resource Name': 'AWS Root Account',
        'Finding': 'No root access keys present',
        'ISO 27001 Control': 'A.9.2',
        'Remediation': 'None required',
        'Status': 'COMPLIANT'
    })

# ============================================================
# CHECK 4: IAM Users without MFA
# ============================================================
# ISO 27001 Control: A.9.4 - Authentication
# MFA = Multi-Factor Authentication. Every user should have it.
print(Fore.YELLOW + "\n[CHECK 4] Checking IAM Users for MFA enablement...")

users_response = iam_client.list_users()
users = users_response['Users']

for user in users:
    total_resources += 1
    username = user['UserName']
    
    # Check if this user has MFA devices set up
    mfa_response = iam_client.list_mfa_devices(UserName=username)
    mfa_devices = mfa_response['MFADevices']
    
    if len(mfa_devices) == 0:
        print(Fore.RED + f"  ❌ HIGH: IAM User '{username}' has NO MFA enabled!")
        findings.append({
            'Severity': 'HIGH',
            'Resource Type': 'IAM User',
            'Resource ID': username,
            'Resource Name': username,
            'Finding': 'IAM user does not have MFA enabled',
            'ISO 27001 Control': 'A.9.4 - System and Application Access Control',
            'Remediation': 'Enable Virtual MFA device for this user via IAM console',
            'Status': 'NON-COMPLIANT'
        })
        remediation_count += 1
    else:
        print(Fore.GREEN + f"  ✅ IAM User '{username}' has MFA enabled")

# ============================================================
# CHECK 5: CloudTrail Enabled
# ============================================================
# ISO 27001 Control: A.12.4 - Logging and Monitoring
print(Fore.YELLOW + "\n[CHECK 5] Verifying CloudTrail is enabled...")

trails_response = cloudtrail_client.describe_trails()
trails = trails_response['trailList']
total_resources += 1

if len(trails) == 0:
    print(Fore.RED + "  ❌ CRITICAL: No CloudTrail trails found! Audit logging is OFF.")
    findings.append({
        'Severity': 'CRITICAL',
        'Resource Type': 'CloudTrail',
        'Resource ID': 'N/A',
        'Resource Name': 'CloudTrail',
        'Finding': 'CloudTrail is not enabled — no audit logs',
        'ISO 27001 Control': 'A.12.4 - Logging and Monitoring',
        'Remediation': 'Enable CloudTrail immediately for all regions',
        'Status': 'NON-COMPLIANT'
    })
    remediation_count += 1
else:
    for trail in trails:
        print(Fore.GREEN + f"  ✅ CloudTrail '{trail['Name']}' is active")
    findings.append({
        'Severity': 'INFO',
        'Resource Type': 'CloudTrail',
        'Resource ID': trails[0]['TrailARN'],
        'Resource Name': trails[0]['Name'],
        'Finding': 'CloudTrail logging is active',
        'ISO 27001 Control': 'A.12.4',
        'Remediation': 'None required',
        'Status': 'COMPLIANT'
    })

# ============================================================
# GENERATE SUMMARY REPORT
# ============================================================
print(Fore.CYAN + "\n" + "=" * 70)
print(Fore.CYAN + "  AUDIT SUMMARY")
print(Fore.CYAN + "=" * 70)

df = pd.DataFrame(findings)

# Count by severity
critical = len(df[df['Severity'] == 'CRITICAL'])
high = len(df[df['Severity'] == 'HIGH'])
compliant = len(df[df['Status'] == 'COMPLIANT'])
non_compliant = len(df[df['Status'] == 'NON-COMPLIANT'])

print(f"\n  Total Resources Scanned : {total_resources}")
print(f"  Total Findings          : {len(findings)}")
print(Fore.RED + f"  Critical Findings       : {critical}")
print(Fore.YELLOW + f"  High Findings           : {high}")
print(Fore.GREEN + f"  Compliant Resources     : {compliant}")
print(Fore.RED + f"  Non-Compliant Resources : {non_compliant}")

if total_resources > 0:
    compliance_percentage = (compliant / total_resources) * 100
    print(f"\n  Overall Compliance Score: {compliance_percentage:.1f}%")

# Save report to Excel
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f"compliance_report_{timestamp}.xlsx"
df.to_excel(report_filename, index=False)
print(Fore.GREEN + f"\n  📊 Report saved: {report_filename}")

# Save JSON report
json_filename = f"compliance_report_{timestamp}.json"
df.to_json(json_filename, orient='records', indent=2)
print(Fore.GREEN + f"  📄 JSON report saved: {json_filename}")

print(Fore.CYAN + "\n" + "=" * 70)
print(Fore.CYAN + "  AUDIT COMPLETE")
print(Fore.CYAN + "=" * 70 + "\n")