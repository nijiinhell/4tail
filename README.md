
This is an automated script designed for bug bounty hunters to streamline the process of subdomain enumeration, fuzzing, and vulnerability scanning. The script utilizes popular open-source tools, including Subfinder, Httpx, Ffuf, and Nuclei, to automate the different steps involved in bug bounty hunting.
Features

    Subdomain Enumeration: The script uses Subfinder to enumerate subdomains of a target domain.
    Aliveness Detection: The script uses Httpx to check the aliveness of the enumerated subdomains.
    Fuzzing: The script uses Ffuf to perform fuzzing on the alive subdomains, utilizing a wordlist for fuzzing.
    Vulnerability Scanning: The script uses Nuclei to perform vulnerability scanning on the alive subdomains, targeting specific tags (e.g., cves, osint, tech).

Prerequisites

    Go installed for Subfinder and Httpx: https://golang.org/dl/
    Ffuf installed: https://github.com/ffuf/ffuf#installation
    Nuclei installed: https://github.com/projectdiscovery/nuclei#install
    Wordlist for fuzzing (e.g., fuzz4bounty.txt): You can find various fuzzing wordlists online or create your own.

Usage

    Clone or download the script to your local machine.
    Make sure all the prerequisites are installed and available in your system.
    Open a terminal and navigate to the directory where the script is located.
    Run the script using the following command: ./subdomain_fuzzing.sh <target_domain>. Replace <target_domain> with the domain you want to target.
    The script will automatically perform subdomain enumeration, aliveness detection, fuzzing, and vulnerability scanning using the configured tools.
    The results will be saved in separate files for each step, including subdomains.txt (subdomain enumeration results), alive_subdomains.txt (alive subdomains), fuzzing_results_<subdomain_file>.txt (fuzzing results for each subdomain), and nuclei_results.txt (vulnerability scanning results).
    You can track the progress and view the results in the terminal as well.

Additional Notes

    The script has special modifications made by the author to enhance its functionality, including adding special commands which are useful for bug bountu, writing fuzzing results to a separate file and displaying them in the terminal for better tracking and management.
    You can customize the fuzzing wordlist, tags for Nuclei scanning, and other parameters in the script to suit your specific needs.
    Always use this script responsibly and follow the rules and regulations of bug bounty programs and ethical hacking practices.
    Further research and improvements can be done to enhance the capabilities of the script and adapt it to different bug hunting scenarios.

Conclusion

The automated subdomain enumeration and fuzzing script is a powerful tool for bug bounty hunters to streamline their workflow and identify potential vulnerabilities in web applications. It simplifies the process of subdomain enumeration, fuzzing, and vulnerability scanning, saving time and effort. The script's special modifications, custom commands, and result tracking make it an effective solution for bug bounty hunting. Please use this script responsibly and follow ethical hacking practices. Happy bug hunting!
