import datetime
from collections import defaultdict, Counter
import matplotlib.pyplot as plt

def analyze_log_file(log_file_path):
    # Initialize variables to store parsed data
    log_data = []
    component_counter = Counter()
    time_counter = defaultdict(lambda: defaultdict(int))

    # Step 1: Open the log file such that only a single line at a time is loaded into memory.
    with open(log_file_path, 'r') as file:
        # Step 2: Parse the log file and record the fields
        for line in file:
            fields = line.split()
            if len(fields) < 6:
                continue  # Skip malformed lines
            try:
                month, day, time_str, level, component_with_pid, *content = fields
                component, process_id = component_with_pid[:-1].split("[")
            except ValueError:
                continue  # Skip lines that can't be parsed correctly

            # Step 3: Create a datetime object to record the date
            dt_str = f"{month} {day} {time_str}"
            dt = datetime.datetime.strptime(dt_str, "%b %d %H:%M:%S")

            # Save parsed data
            log_data.append({
                "month": month,
                "day": day,
                "time": dt.time(),
                "level": level,
                "component": component,
                "process_id": process_id,
                "content": " ".join(content)
            })

            # Count component occurrences
            component_counter[component] += 1

            # Count component occurrences by time of day
            if dt.time() >= datetime.time(9, 0) and dt.time() <= datetime.time(17, 0):
                period = "Working Hours"
            else:
                period = "After Hours"
            time_counter[component][period] += 1

    # Step 4: Find and print the three most commonly used components
    common_components = component_counter.most_common(3)
    print("Three most commonly used components:", common_components)

    # Brief Descriptions of Components (Step 5):
    # Commenting on the nature of common components based on general understanding
    # 
    # ftpd: FTP daemon component, responsible for managing FTP connections.
    # sshd(pam_unix): Secure Shell Daemon with PAM for UNIX, responsible for SSH connections and authentication.
    # su(pam_unix): Related to the 'su' command, allows a user to run a command with substitute user and group ID, integrated with PAM for UNIX.

    # Step 6: Create a plot showing component usage by time of day
    # Initialize the data for plotting
    
    plot_data = {'Working Hours': [], 'After Hours': []}
    labels = []

    # Prepare the data
    for component, _ in common_components:
        labels.append(component)
        plot_data['Working Hours'].append(time_counter[component].get('Working Hours', 0))
        plot_data['After Hours'].append(time_counter[component].get('After Hours', 0))

    # Create the plot
    fig, ax = plt.subplots()
    width = 0.35  # Width of the bars
    x = range(len(common_components))

    # Plot Working Hours
    ax.barh([i - width/2 for i in x], plot_data['Working Hours'], width, label='Working Hours (9 AM - 5 PM)')

    # Plot After Hours
    ax.barh([i + width/2 for i in x], plot_data['After Hours'], width, label='After Hours')

    # Add some text for labels, title and custom x-axis tick labels
    ax.set_xlabel('Number of Entries')
    ax.set_title('Component Usage by Time of Day')
    ax.set_yticks(x)
    ax.set_yticklabels(labels)
    ax.legend()

    plt.show()

if __name__ == "__main__":
    log_file_path = "Files/part2.log"
    analyze_log_file(log_file_path)
