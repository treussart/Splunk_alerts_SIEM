#!/usr/bin/python3
# coding: utf8
import json
import ast
import os
import sys
import subprocess
import smtplib
import argparse
from email.mime.text import MIMEText
from datetime import datetime, timedelta


def send_email(from_address, to_address, body, nbr):
    msg = MIMEText("<html><head></head><body>" + str(body) + "</body></html>", 'html')
    msg['Subject'] = '%s Alerts from SIEM' % nbr
    msg['From'] = from_address
    msg['To'] = to_address
    # Send the message via our own SMTP server.
    s = smtplib.SMTP('localhost')
    s.send_message(msg)
    s.quit()


def get_alerts(query, hours):
    now = datetime.now()
    earliest_time = now - timedelta(hours=hours)
    current_path = os.path.dirname(os.path.abspath(__file__))
    shell = "python " + current_path + "/splunk-sdk-python/search.py " \
            "--output_mode=json --earliest_time=" + earliest_time.isoformat() + \
            " 'search " + query + " '"
    return json.loads(subprocess.getoutput(shell))


def alert_splunk(from_address, to_address, time_period, severity):
    """Main function."""
    suricata_query = "index=suricata event_type=alert"
    ossec_query = "index=ossec"
    list_alerts = ""
    nbr = 0
    alerts_suricata = get_alerts(suricata_query, time_period)
    for alert in alerts_suricata['results']:
        alert_raw = ast.literal_eval(alert['_raw'])
        if int(alert_raw['alert']['severity']) >= severity:
            nbr += 1
            list_alerts = list_alerts + "<h4>" + str(alert_raw['alert']['signature']) + \
                          "</h4>" + "<pre>" + alert['_raw'] + "</pre><br/>"
    alerts_ossec = get_alerts(ossec_query, time_period)
    for alert in alerts_ossec['results']:
        alert_raw = ast.literal_eval(alert['_raw'])
        if int(alert_raw['rule']['level']) >= severity:
            nbr += 1
            list_alerts = list_alerts + "<h4>" + str(alert_raw['rule']['comment']) + \
                          "</h4>" + "<pre>" + alert['_raw'] + "</pre><br/>"
    if list_alerts:
        send_email(from_address, to_address, list_alerts, nbr)


if __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/splunk-sdk-python")
    parser = argparse.ArgumentParser()
    parser.add_argument("--time_period",
                        help="the elapsed time to check",
                        type=int,
                        default=2)
    parser.add_argument("--severity",
                        help="the level severity to consider",
                        type=int,
                        default=6)
    parser.add_argument("--from_address",
                        help="The address who send the email",
                        default="alert@treussart.com")
    parser.add_argument("--to_address",
                        help="The address who receive the email",
                        default="matthieu@treussart.com")
    args = parser.parse_args()
    time_period = args.time_period
    severity = args.severity
    from_address = args.from_address
    to_address = args.to_address
    alert_splunk(from_address, to_address, time_period, severity)
