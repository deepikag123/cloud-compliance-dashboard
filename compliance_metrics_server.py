import time
import threading
import boto3
from prometheus_client import start_http_server, Gauge, Counter
from datetime import datetime

# GAUGES — metrics that can go up and down (like temperature)
# A Gauge holds a single numeric value that can increase or decrease

# Total non-compliant resources found
non_compliant_gauge = Gauge(
    'aws_non_compliant_resources_total',
    'Total number of non-compliant AWS resources',
    ['severity']  # Label: we separate by CRITICAL, HIGH, etc.
)

# Compliance score percentage
compliance_score_gauge = Gauge(
    'aws_compliance_score_percentage',
    'Overall compliance score as percentage (0-100)'
)

# Resources scanned
resources_scanned_gauge = Gauge(
    'aws_resources_scanned_total',
    'Total number of AWS resources scanned'
)

# Last scan time (Unix timestamp)
last_scan_gauge = Gauge(
    'aws_last_compliance_scan_timestamp',
    'Unix timestamp of last compliance scan'
)

def run_compliance_check():
    """
    This function runs the actual compliance checks
    and updates Prometheus metrics
    """
    session = boto3.Session(region_name='ap-south-1')
    ec2_client = session.client('ec2')
    s3_client = session.client('s3')
    iam_client = session.client('iam')

    critical_count = 0
    high_count = 0
    compliant_count = 0
    total = 0

    # Check Security Groups
    paginator = ec2_client.get_paginator('describe_security_groups')
    for page in paginator.paginate():
        for sg in page['SecurityGroups']:
            total += 1
            is_compliant = True
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        if from_port <= 22 <= to_port:
                            critical_count += 1
                            is_compliant = False
            if is_compliant:
                compliant_count += 1

    # Check S3 Buckets
    buckets = s3_client.list_buckets()['Buckets']
    for bucket in buckets:
        total += 1
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket['Name'])
            config = pab['PublicAccessBlockConfiguration']
            if not all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ]):
                high_count += 1
            else:
                compliant_count += 1
        except:
            high_count += 1

    # Update Prometheus Gauges
    non_compliant_gauge.labels(severity='CRITICAL').set(critical_count)
    non_compliant_gauge.labels(severity='HIGH').set(high_count)
    resources_scanned_gauge.set(total)
    last_scan_gauge.set(datetime.now().timestamp())

    if total > 0:
        score = (compliant_count / total) * 100
        compliance_score_gauge.set(score)

    print(f"[{datetime.now()}] Metrics updated — Score: {(compliant_count/total*100):.1f}% | Critical: {critical_count} | High: {high_count}")

def metrics_loop():
    """Run compliance check every hour"""
    while True:
        run_compliance_check()
        time.sleep(3600)  # 3600 seconds = 1 hour

if __name__ == '__main__':
    # Start the HTTP server on port 8000
    # Prometheus will call http://localhost:8000/metrics every hour
    start_http_server(8000)
    print("Compliance metrics server started on port 8000")
    print("Prometheus can now scrape at http://localhost:8000/metrics")

    # Run first check immediately
    run_compliance_check()

    # Then run in background thread every hour
    thread = threading.Thread(target=metrics_loop, daemon=True)
    thread.start()

    # Keep main thread alive
    while True:
        time.sleep(60)