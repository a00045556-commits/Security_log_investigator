import os
from collections import Counter
import csv

#Project folder path
base_dir = os.path.dirname(os.path.abspath(__file__))
#data folder path
data_dir = os.path.join(base_dir, 'Data')
#reports folder path
report_dir = os.path.join(base_dir, 'Reports')

#function to load data from log files
def load_data(filename):
    """Read a log file and return its lines."""
    file_path = os.path.join(data_dir, filename)
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        return lines
    #when file is not found, print error message and return empty list
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found in the 'Data' directory.")
        return []
    #when an OS error occurs, print error message and return empty list
    except OSError as error:
        print(f"Error: {filename}: {error}")
        return []

#function to check all log entries
def parse_firewall_line(line):
    #splits and separates the line in to parts
    parts = line.strip().split()
    
    if len(parts)!= 8:
        return None
    
    try:
        timestamp = parts[0] + " " + parts[1]
        action = parts[2]
        #empty dictionary to store the fields
        fields = {}
        #extracts the key value pairs from the log line and stores them in the fields dictionary
        for item in parts [3:]:
            key, value = item.split ('=', 1)
            fields[key] = value
        #checks if info exsists in the fields dictionary
        required_fields = ["src", "dst", "proto", "port", "bytes"]
        for field in required_fields:
            #error handling
            if field not in fields:
                return None
     
        if action not in ["ALLOWED", "BLOCKED"]:
            return None
        
        if fields["proto"] not in ["TCP", "UDP",]:
            return None
        
        port = int(fields["port"])
        byte_count = int(fields["bytes"])
        
        if port <1 or port > 65535 or byte_count < 0:
            return None
        
        return {
            "timestamp": timestamp,
            "action": action,
            "src": fields["src"],
            "dst": fields["dst"],
            "proto": fields["proto"],
            "port": port,
            "bytes": byte_count
        }
        
    except (ValueError, TypeError):
        return None
    
   #use if you want to test the function with a sample log line
#firewall_lines = load_data("firewall.log")
#if firewall_lines:
#    result = parse_firewall_line(firewall_lines[0])
#print(result)

# function to analyse the firewall activity
def analyse_firewall():
    firewall_lines = load_data("firewall.log")
    
    events = []
    invalid_lines = 0

#check each firewall entry and parse it, if valid add to events list, if invalid increment invalid_lines counter
    for line in firewall_lines:
        event = parse_firewall_line(line)

        if event is None:
            invalid_lines += 1
        else:
            events.append(event)
    
    #count allowed and blocked connections 
    allowed_count = sum(1 for event in events if event["action"] == "ALLOWED")
    blocked_count = sum(1 for event in events if event["action"] == "BLOCKED")
    
    #count unique source IP (ensure to avoid duplicates)
    unique_ips = len(set(event["src"] for event in events))
    
    #most frequently blocked ip
    blocked_ips = Counter(event["src"] for event in events if event["action"] == "BLOCKED")
    
    #most common targeted port
    targeted_ports = Counter(event["port"] for event in events)
    
    return {
        "total_events" : len(events),
        "invalid_lines" : invalid_lines,
        "allowed_count" : allowed_count,
        "blocked_count" : blocked_count,
        "unique_ips" : unique_ips,
        "top_blocked_ip": blocked_ips.most_common(5),
        "top_ports": targeted_ports.most_common(5)  
        
    }
    
    # Test the firewall analysis function
    #firewall_results = analyse_firewall()

#print("\n--- FIREWALL ANALYSIS ---")

#for key, value in firewall_results.items():
#   print(f"{key}: {value}")

#authentication logs function
def parse_authentication_line(line):
    
    parts = line.strip().split()
    
    if len(parts) != 7:
        return None
    
    try:
        timestamp = parts[0] + " " + parts[1]
        event = parts[2]
        
        fields = {}
        
        for item in parts [3:]:
            key, value = item.split('=', 1)
            fields[key] = value
            
        required_fields = ["user", "src", "host", "method"]
        
        for field in required_fields:
            if field not in fields:
                return None
            
            if not event:
                return None
            
            return{
                "timestamp": timestamp,
                "event": event,
                "user": fields["user"],
                "src": fields["src"],
                "host": fields["host"],
                "method": fields["method"]
            }
            
    except (ValueError, TypeError):
        return None
 # Test the authentication parsing function
 #auth_lines = load_data("authentication.log")

#if auth_lines:
#   result = parse_authentication_line(auth_lines[0])
#   print(result)
    
#authentication analysis function
def analyse_authentication():
    
    auth_lines = load_data("authentication.log")
        
    events = []
    invalid_lines = 0
    
    # parse each authentication entry
    for line in auth_lines:
        event = parse_authentication_line(line)
        
        if event is None:
            invalid_lines += 1
        else:
            events.append(event)
    
    #count successful and failed logins
    success_count = sum(1 for event in events if event["event"] == "LOGIN_SUCCESS")
    
    failed_count = sum(1 for event in events if event["event"] == "LOGIN_FAILED")
    
    lock_count = sum(1 for event in events if "LOCK" in event["event"].upper() and "UNLOCK" not in event["event"].upper())
    
    failed_ips = Counter(event["src"] for event in events if event["event"] == "LOGIN_FAILED")
    
    failed_users = Counter(event["user"] for event in events if event["event"] == "LOGIN_FAILED")
    
    return {
        "total_events": len(events),
        "invalid_lines": invalid_lines,
        "successful_logins": success_count,
        "failed_logins": failed_count,
        "account_locks": lock_count,
        "top_failed_ips": failed_ips.most_common(5),
        "top_failed_users": failed_users.most_common(5)
    }

# Test authentication analysis
#auth_results = analyse_authentication()
#print("\n--- AUTHENTICATION ANALYSIS ---")

#for key, value in auth_results.items():
#   print(f"{key}: {value}")
    
# Function to load a suspicious IPs
def load_suspicious_ips():

    file_path = os.path.join(data_dir, "suspicious_ips.txt")
    #use of lists to contain the suspicious IPs
    try:
        with open(file_path, 'r') as file:
            suspicious_ips = []
            
            for line in file:
                ip = line.strip()
                
                if ip:
                    suspicious_ips.append(ip)
            return suspicious_ips
            
    except FileNotFoundError:
        print(f"Error: suspicious_ips.txt file not found.")
        return[]
    
    except OSError as error:
        print(f"Error reading suspicious IP file: {error}")
        return []
    
    # Test suspicious IP loading
 #suspicious_ips = load_suspicious_ips()
 #print("\n--- SUSPICIOUS IP ADDRESSES ---")
 #print(suspicious_ips)
 #print(f"Total suspicious IPs: {len(suspicious_ips)}")
 

# Function to analyse suspicious IPs
def analyse_suspicious_ips():
    suspicious_ips = load_suspicious_ips()
    results = []
    #store info in a list
    

    firewall_lines = load_data("firewall.log")
    auth_lines = load_data("authentication.log")

   

    for ip in suspicious_ips:
        blocked_connections = 0
        failed_logins = 0
        firewall_matches = 0
        auth_matches = 0

        # Check firewall logs
        for line in firewall_lines:
            event = parse_firewall_line(line)

            if event is not None and event["src"] == ip:
                firewall_matches += 1

                if event["action"] == "BLOCKED":
                    blocked_connections += 1

        # Check authentication logs
        for line in auth_lines:
            event = parse_authentication_line(line)

            if event is not None and event["src"] == ip:
                auth_matches += 1

                if event["event"] == "LOGIN_FAILED":
                    failed_logins += 1


        # Check which logs contain the IP
        if firewall_matches > 0 and auth_matches > 0:
            appears_in = "Both log files"
        elif firewall_matches > 0:
            appears_in = "Firewall log only"
        elif auth_matches > 0:
            appears_in = "Authentication log only"
        else:
            appears_in = "Neither log file"

        # Explain suspicious activity
        if blocked_connections >= 10 or failed_logins >= 10:
            reason = "High level of suspicious activity detected."
        elif blocked_connections > 0 or failed_logins > 0:
            reason = "Some suspicious activity detected."
        else:
            reason = "No matching activity found in the logs."
      
        #adds the results into the list
        results.append({
        "IP Address": ip,
        "Blocked Connections": blocked_connections,
        "Failed Login Attempts": failed_logins,
        "Firewall Matches": firewall_matches,
        "Authentication Matches": auth_matches,
        "Appears in": appears_in,
        "Reason": reason})
    return results
 
# report geneneration function -> into csv file
def generate_report():
    #storage for data from the 3 functions 
    firewall_results = analyse_firewall()
    auth_results = analyse_authentication()
    suspicious_ips = load_suspicious_ips()
    suspicious_results = analyse_suspicious_ips()
    
    report_path = os.path.join(report_dir, "security_report.csv")
    try: 
        with open(report_path, 'w', newline='') as file:
        #creates a CSV report
            writer = csv.writer(file)
            #Writes the report header
            writer.writerow(["Security Report"])
            writer.writerow([])
            
            #writes the firewall analysis section
            writer.writerow(["FIREWALL ANALYSIS"])
            writer.writerow(["Metric", "Result"])
            for key, value in firewall_results.items():
                writer.writerow([key, value])
            writer.writerow([])
            
            #writes the authentication analysis section
            writer.writerow(["AUTHENTICATION ANALYSIS"])
            writer.writerow(["Metric", "Result"])
            for key, value in auth_results.items():
                writer.writerow([key, value])
            writer.writerow([])
            
            #writes a list suspicious IP addresses section
            writer.writerow(["SUSPICIOUS IP ADDRESSES"])
            writer.writerow(["IP Address"])

            for ip in suspicious_ips:
                writer.writerow([ip])

            writer.writerow([]) 
         
           # writes the suspicious IP investigation section
            writer.writerow(["SUSPICIOUS IP INVESTIGATION"])

            for result in suspicious_results:
                writer.writerow(["IP Address", result["IP Address"]])
                writer.writerow(["Blocked Connections", result["Blocked Connections"]])
                writer.writerow(["Failed Login Attempts", result["Failed Login Attempts"]])
                writer.writerow(["Firewall Matches", result["Firewall Matches"]])
                writer.writerow(["Authentication Matches", result["Authentication Matches"]])
                writer.writerow([])
        
            print(f"Report generated successfully at: {report_path}")
    except OSError as error:
        print(f"Error generating report: {error}")
     
 
 
 # Main menu function
def main():
#while loop keeps program running until user selects exit option
    while True:

        print("\n===== SECURITY LOG INVESTIGATOR =====")
        print("1. Analyse Firewall Logs")
        print("2. Analyse Authentication Logs")
        print("3. View Suspicious IP Addresses")
        print("4. Generate CSV Security Report")     
        print("5. Exit")

        choice = input("\nPlease select an option (1-5):")
    #firewall analysis option
        if choice == "1":

            results = analyse_firewall()

            print("\n--- FIREWALL ANALYSIS ---")

            for key, value in results.items():
                print(f"{key}: {value}")

        elif choice == "2":

            results = analyse_authentication()
    #authentication analysis option
            print("\n--- AUTHENTICATION ANALYSIS ---")

            for key, value in results.items():
                print(f"{key}: {value}")

        elif choice == "3":
            suspicious_ips = load_suspicious_ips()
            results = analyse_suspicious_ips()

            print("\n--- SUSPICIOUS IP INVESTIGATION ---")

            for result in results:
                for key, value in result.items():
                    print(f"{key}: {value}")
                print("-" * 40)
            print("\n--- SUSPICIOUS IP ADDRESSES ---")

            for ip in suspicious_ips:
                print(ip)

        elif choice == "4":
            generate_report()

        elif choice == "5":

            print("Exiting Security Log Investigator. Goodbye!")
            break

        else:
            print("Invalid selection. Please choose between 1 and 5.")


# Start the program
if __name__ == "__main__":
    main()