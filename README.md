Honeypot Hawk Version 2 (WIP)
==============================
Currently in the process of turning this repo into the second version of Hawk Honeypots, this time with a new name and not spending ages making a React frontend.

Features
-----------------
- Detects and reports brute-force attacks on common services such as Telnet and SSH.
- Detects and reports port scanners.
- Easy to deploy.
- Highly customizable.
- Can be hooked into AbuseIPDB, a database dedicated to reporting such malicious activities.

How to use
-----------------
1) You must be using Python 3.6 or newer.
2) Download the source code, or use `git clone` to clone this repository to a directory of your choosing.
3) Use `pip install -r requirements.txt` to install the required dependencies.
4) Edit `config.yml` to configure the behavior of the honeypots.
5) Run the Python file corresponding to the honeypot you wish to run, and you're set!
6) If you wish for the honeypots to remain running after you close the terminal or log out of SSH, then you should use `python hawk_honeypots.py &` or look into using `screen`.