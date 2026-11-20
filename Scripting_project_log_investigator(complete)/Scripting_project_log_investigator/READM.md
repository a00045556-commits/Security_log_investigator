Scripting_poject_log_investigator

Overview
This is a Python program used to analyse security log files. A menu is displayed when it is started and depending on which option is picked, it analyses firewall activities, authentication events and suspicious IP address to scope out potentially harmful behaviour. 
The program also creates a csv file of its findings when the option is picked in the menu displaying the summary of all the analysis named above

Features
 * Firewall analysis
 * Authentication log analysis
 * Investigation of suspicious IP addresses 
 * CSV generation
 * Error handling for missing files and invalid log entries
 * Menu driven interface

```Project structure
Scripting_project_log_investigator/
│
├── Data/
│   ├── authentication.log
│   ├── firewall.log
│   ├── suspicious_ips.txt
│   └── README.txt
│
├── Reports/
│   └── security_report.csv
│
├── Log_investigator.py
├── README.md
└── requirements.txt

Requirements
* Python 3
* Files from Data folder (all the log files and suspicious IP list)

How to run
1. Download/clone the file
2. Check that the Data folder contains all the logs/lists needed
3. Open terminal in the Scripting_project_log_investigator/
4. Run program : python Log_investigator.py

Menu
The program starts up a menu with options 1 - 5
1. Analyse Firewall logs
2. Analyse Authentication logs
3. View suspicious IP addresses
4. Generate CSV security reports
5. Exit

Outputs
1. Firewall log analysis - Identification of allowed and blocked connections
2. Authentication log analysis - Checks failed login attempts
3. Investigation of suspicious IP addresses - checks if suspicious IP addresses appear in either logs
4. CSV Report is generated
5. Exits the program

Data
Uses the log files and suspicious IP addresses within the Data/ which is supplied by the project brief. The program is designed to analyse these and provide an output to reflect the findings in these logs and sumarise them  

