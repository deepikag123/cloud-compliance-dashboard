from prometheus_client import start_http_server, Gauge
import time, random

# Existing metrics
compliance_score = Gauge('aws_compliance_score_percentage', 'Overall AWS compliance score')
failed_controls = Gauge('aws_failed_controls_total', 'Number of failed compliance controls')
passed_controls = Gauge('aws_passed_controls_total', 'Number of passed compliance controls')

# New metrics for dashboard
non_compliant_critical = Gauge('aws_non_compliant_resources_total', 'Non-compliant resources', ['severity'])
resources_scanned = Gauge('aws_resources_scanned_total', 'Total resources scanned')
ec2_cpu = Gauge('aws_ec2_cpuutilization_average', 'EC2 CPU utilization average')
last_scan = Gauge('aws_last_compliance_scan_timestamp', 'Last compliance scan Unix timestamp')

def collect_metrics():
    score = random.uniform(72, 95)
    failed = random.randint(5, 20)
    passed = random.randint(80, 120)

    compliance_score.set(score)
    failed_controls.set(failed)
    passed_controls.set(passed)

    # New metrics
    non_compliant_critical.labels(severity='CRITICAL').set(random.randint(2, 6))
    non_compliant_critical.labels(severity='HIGH').set(random.randint(1, 4))
    resources_scanned.set(random.randint(10, 20))
    ec2_cpu.set(random.uniform(5, 85))
    last_scan.set(time.time())

if __name__ == '__main__':
    start_http_server(8000)
    print("Compliance metrics server running on port 8000")
    while True:
        collect_metrics()
        time.sleep(30)