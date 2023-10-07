import re
from datetime import datetime as dt
import matplotlib.pyplot as plt
from collections import Counter

def parsemb(log_entry):
    pattern = r'^(?P<ts>[0-9]{2}:[0-9]{2}:[0-9]{2})\s:\s(?P<client_hostname>[a-zA-Z0-9\-]+)\|(?P<client_ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
    
    log_data = re.search(pattern, log_entry)  # Match the regex with the log entry
    
    if not log_data:
        return None

    r = log_data.groupdict()  # Create a dictionary from the regex match
    r['ts'] = dt.strptime(r['ts'], "%H:%M:%S")  # Convert the time string into a datetime object

    return r

def plotBarChart(events, users):
    plt.subplot(211)
    plt.bar(range(len(events)), list(events.values()), align="center")
    plt.xticks(range(len(events)), list(events.keys()))
    
    plt.subplot(212)
    plt.bar(range(len(users)), list(users.values()), align="center")
    plt.xticks(range(len(users)), list(users.keys()))
    
    plt.show()

def getBaseTs(ts, interval):
    # Divide an hour into the interval number of sections
    interval = int(60 / interval)
    hours = ts.time().hour
    minutes = ts.time().minute
    base_minutes = int(minutes / interval) * interval
    
    return "{}:{}".format(hours, base_minutes)
