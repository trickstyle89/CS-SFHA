import re
from datetime import datetime
from collections import Counter
import matplotlib.pyplot as plt

# Define a function to process the log file
def process_log(filename):
    # Regular expression pattern to extract the necessary log components
    pattern = r'(\w+ \d+ \d+:\d+:\d+) (\w+) (\w+\(.*\))\[\d+\]: (.+)'
    
    components = []

    # Open the log file and process line by line
    with open(filename, 'r') as f:
        for line in f:
            match = re.match(pattern, line)
            if match:
                # Extract the matched groups
                date_str, level, component, content = match.groups()
                
                # Convert the date string to a datetime object
                date = datetime.strptime(date_str, '%b %d %H:%M:%S')
                
                components.append((date, component))
                
    return components

# Process the log file
components = process_log('Files/part2.log')

# Extract and count the components
component_counts = Counter([component for _, component in components])

# Get the three most common components
common_components = [component[0] for component in component_counts.most_common(3)]

print("Three most commonly used components:")
for comp in common_components:
    print(comp)

# Comments:
# 1. sshd(pam_unix): This component logs SSH-related events, particularly those related to user authentication.
# 2. [Next common component]: Brief description...
# 3. [Next common component]: Brief description...

# Analyze the usage of these components over the day
working_hours_count = Counter()
after_hours_count = Counter()

for date, component in components:
    if component in common_components:
        if 9 <= date.hour <= 17:  # Working hours: 9am to 5pm inclusive
            working_hours_count[component] += 1
        else:
            after_hours_count[component] += 1

# Plotting the data
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
