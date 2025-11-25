**Secure File Vault**

  A secure, Flask-based file storage system featuring optional client-side encryption.

**Features**

  _Client-Side Encryption_: Users can encrypt files locally using the Web Crypto API (AES-GCM) before they ever leave the browser. The server never sees the plaintext file or the passphrase.

  _Secure Backend_: Built with Flask, using JWT (JSON Web Tokens) for secure authentication.

 _Zero-Config Database_: Uses SQLite for an automatic, serverless database setup.

  _Responsive UI_: A clean interface built with Tailwind CSS.

**How to Run Locally**

  1. Clone the repository (or download the files):

    git clone https://github.com/YOUR_USERNAME/secure-file-storage.git
    cd secure-file-storage


  2. Install Dependencies:

    pip install -r requirements.txt


  3. Start the Server:

    python app.py


  4. Open in Browser:
  
    http://127.0.0.1:5000

**Deployment**

  This project is designed to be deployed on **PythonAnywhere**.

**Quick Deployment Steps:**

  1. Push this code to GitHub.

  2. Pull the code into a PythonAnywhere Bash console.

  3. Set up a Flask Web App in the PythonAnywhere dashboard.

  4. Point the WSGI configuration file to app.py.


**Tech Stack**

_Frontend_: HTML5, Tailwind CSS, Vanilla JavaScript

_Backend_: Python 3, Flask, SQLAlchemy

_Database_: SQLite

