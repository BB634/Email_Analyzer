EMAIL ANALYZER – USER GUIDE
===========================

This tool allows you to paste raw email content and inspect it for potential threats 
such as suspicious links, unauthorized senders, and mail relay chains.

REQUIREMENTS
------------
- A Windows or Mac computer
- Internet connection
- An IPinfo.io API token (register for free at https://ipinfo.io/)

STEP 1: GET IPINFO.IO API TOKEN
-------------------------------
1. Visit https://ipinfo.io/signup and create a free account.
2. After signing in, go to your dashboard and copy your API token.
3. Set it as an environment variable named IPINFO_TOKEN before running the program.

   On Windows:
     set IPINFO_TOKEN=your_token_here

   On Mac/Linux:
     export IPINFO_TOKEN=your_token_here

STEP 2: INSTALL PYTHON
----------------------
1. Go to https://www.python.org/downloads
2. Click the "Download Python 3.x.x" button.
3. Run the installer file.
4. IMPORTANT: On the first screen, check the box that says:
   ✓   [ ] Add Python to PATH
5. Click "Install Now" and follow the instructions.

STEP 3: INSTALL REQUIRED LIBRARIES
----------------------------------
1. Open Command Prompt (Windows) or Terminal (Mac):

   On Windows:
   - Press the Windows key, type `cmd`, and hit Enter.

   On Mac:
   - Open Terminal from Applications > Utilities.

2. Enter this command and press Enter:

   pip install flask flask-cors beautifulsoup4 python-whois requests

STEP 4: SET UP FILES
---------------------
1. Create a folder anywhere, such as:
   Documents\Email_Analyzer

2. Save these files into that folder:
   - backend.py (the program engine)
   - frontend.html (the browser interface)

STEP 5: RUN THE ANALYZER
-------------------------
1. In the command window, go to the folder where your files are saved:
   cd C:\Users\YourName\Documents\Email_Analyzer

2. Start the program:
   python backend.py

3. Open your web browser and go to:
   http://127.0.0.1:5000

STEP 6: ANALYZE AN EMAIL
------------------------
1. Copy and paste the full raw email (including headers) into the text box.
2. Click “Analyze”.
3. The interface will show:
   - Authentication status (SPF, DKIM, DMARC)
   - Sender details
   - Domain age
   - Suspicious redirect links
   - Relay hops from source to inbox

DISCLAIMER & LIABILITY
-----------------------
This software is provided for educational and informational purposes only. Use it at 
your own risk.

It is not affiliated with, endorsed by, or distributed on behalf of any organization, 
employer, or commercial entity. The author makes no warranties or guarantees, express or 
implied, including but not limited to accuracy, security, or reliability.

By using this tool, you acknowledge that the developers are not responsible for any 
direct, indirect, incidental, or consequential damages arising from its use.

SECURITY NOTE
--------------
Do not analyze sensitive or private email content unless you understand the privacy 
risks of doing so on your machine. This tool is designed for local use only.
