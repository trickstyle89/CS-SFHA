import re
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt

def get_description(component):
    descriptions = {
        "sshd(pam_unix)": "SSH-related events, particularly user authentication. Repeated failures can indicate a brute force attempt.",
        "su(pam_unix)": "Events related to the 'su' command, indicating user account switching.",
        "ftpd": "FTP-related events, indicating incoming connections for file transfers.",
        "logrotate": "Manages the rotation and archiving of log files.",
        "cups": "Events related to the Common Unix Printing System.",
        "syslogd": "System logger that handles logging of system messages and warnings.",
        "gdm(pam_unix)": "Events related to the GNOME Display Manager (GDM), typically indicating user login/logout activities on a GUI desktop."
    }
    return descriptions.get(component, "No description available for this component.")


def process_log(filename):
    pattern = r'(\w+ \d+ \d+:\d+:\d+) (\w+) (\w+\(.*\))\[\d+\]: (.+)'
    components = []

    with open(filename, 'r') as f:
        for line in f:
            match = re.match(pattern, line)
            if match:
                date_str, level, component, content = match.groups()
                date = datetime.strptime(date_str, '%b %d %H:%M:%S')
                components.append((date, component))
                
    return components

components = process_log('Files/part2.log')
component_counts = Counter([component for _, component in components])
common_components = [component[0] for component in component_counts.most_common(3)]

print("Three most commonly used components with their descriptions:")
for comp in common_components:
    print(f"{comp}: {get_description(comp)}")

working_hours_count = Counter()
after_hours_count = Counter()

for date, component in components:
    if component in common_components:
        if 9 <= date.hour <= 17:  # Working hours: 9am to 5pm inclusive
            working_hours_count[component] += 1
        else:
            after_hours_count[component] += 1

labels = common_components
working_hours_values = [working_hours_count[component] for component in common_components]
after_hours_values = [after_hours_count[component] for component in common_components]

x = range(len(labels))
plt.bar(x, working_hours_values, width=0.4, label='Working Hours', color='b', align='center')
plt.bar(x, after_hours_values, width=0.4, label='After Hours', color='r', bottom=working_hours_values, align='center')

plt.xlabel('Components')
plt.ylabel('Counts')
plt.title('Component Usage During Different Periods of the Day')
plt.xticks(x, labels, rotation=45)
plt.legend()
plt.tight_layout()
plt.show()