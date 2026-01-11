<div align="center">
    <img src="images/IOC_Analyzer_transp.png" alt="IOC Analyzer Logotyp" width="500"/>
</div>

# IOC Analyzer

**Version:** 1.0.0

**Developer:** Daniel Hållbro (Student)

A Python script designed to automatically analyze Indicators of Compromise (IOCs) such as IP addresses, URLs, and hashes. The tool aggregates data from multiple sources (VirusTotal, AbuseIPDB, IPinfo) to provide a quick and comprehensive threat overview.

---

## Table of Contents

* [IOC Analyzer](#ioc-analyzer)
* [Features](#features)
* [Requirements](#requirements)
* [Configuration](#configuration)
* [API Key Acquisition](#api-key-acquisition)
* [Usage](#usage)
* [Project Structure](#project-structure)
* [Security Note](#security-note)
* [Contributing](#contributing)

---

## Features

* **Multisource Analysis:** Integrates data from VirusTotal, AbuseIPDB, and IPinfo.
* **IP Analysis:** Retrieves threat reputation, Abuse Score, and geolocation/ASN data.
* **URL/Hash Analysis:** Uses VirusTotal for threat reputation and file/URL data.
* **Caching:** Caches results (default 1 day) to avoid unnecessary API calls and conserve quotas.
* **Operating Modes:** Supports interactive mode and non-interactive CLI mode.
* **Reporting:** Ability to output analysis results to a dedicated report file.
* **Multiple platform usage:** Can be run on Linux, Windows and macOS systems.

<small>[To the top](#ioc-analyzer)</small>
---

## Requirements

* Python 3.x
* The libraries specified in `requirements.txt`: `requests`, `python-dotenv`.

### Installation (Recommended Method)

The standard and most reliable way to install the required dependencies is by using a virtual environment and `pip`.

#### 1. Project Setup

1.  **Clone or Download the Project:**
    ```bash
    git clone [Your Git URL Here]
    cd IOC_Analyzer
    ```

2.  **OPTIONAL: Set up a Virtual Environment:**
    (A virtual environment (`venv`) is highly recommended to keep the project's dependencies isolated from your system's main Python installation.)

    |       OS        | Command to Create Virtual Environment |    Command to Activate     |
    | --------------- |  -----------------------------------  |  ------------------------  |
    | **Linux/macOS** |        `python3 -m venv venv`         | `source venv/bin/activate` |
    |   **Windows**   |        `python -m venv venv`          | `.\venv\Scripts\activate`  |

3.  **Install Dependencies:**
    With the virtual environment activated, use `pip` to install the packages from the provided `requirements.txt` file:

    ```bash
    pip install -r requirements.txt
    ```

<small>[To the top](#ioc-analyzer)</small>
---

## Configuration

The tool requires API keys (tokens) to operate. These should be stored in a separate environment file (`.env`) for security.

1.  **Create the `.env` File:**
    Create a file named **`.env`** in the root directory of the project (IOC_Analyzer/ by default).

2.  **Add API Keys:**
    **VirusTotal (VT\_API\_KEY) is mandatory**. The others are optional but recommended for full analysis.

    ```bash
    # CRITICAL REQUIREMENT. Key should be inserted within the qoutations ''
    VT_API_KEY='your_virustotal_api_key'

    # OPTIONAL APIs. Key should be inserted within the qoutations ''
    ABUSE_API_KEY='your_abuseipdb_api_key'
    IPINFO_API_KEY='your_ipinfo_api_key'
    ```

<small>[To the top](#ioc-analyzer)</small>
---

## API Key Acquisition

This tool requires API keys from the following three services to function correctly. All services offer a free/community tier suitable for typical usage.

### 1. VirusTotal (VT)

* **Service:** Provides reputation scores and detailed context for file hashes, domains, IPs, and URLs.
* **Acquisition:**
    1.  Create an account on the official VirusTotal website.
    2.  Navigate to **API Key** option in the dropdown menu (top right corner of your browser).
    3.  Locate and copy your **API Key**.

### 2. AbuseIPDB

* **Service:** Used to report and check the abuse confidence score for public IP addresses.
* **Acquisition:**
    1.  Register an account on the AbuseIPDB website.
    2.  Go to the **API** section in your dashboard.
    3.  Generate and copy your personal **API Key**.

### 3. IPinfo

* **Service:** Provides geolocation, hosting provider, and other critical metadata for IP addresses.
* **Acquisition:**
    1.  Sign up for an account on the IPinfo website.
    2.  Access your **Dashboard** or **Account** settings.
    3.  Copy the **Access Token** (which serves as your API Key).


Once you have acquired these three keys, place them in the appropriate environment variables in your **`.env`** file, as detailed in the **Configuration** section.

<small>[To the top](#ioc-analyzer)</small>
---

## Usage

The script can be run in two modes: interactive (default) and non-interactive (CLI).

### 1. Interactive Mode (Standard)

Run the script without any arguments. It will prompt you for an IOC to analyze.

python3 main.py

#### Example using Kali Linux:

<img src="images/Interactive_No_Flag.png" alt="Interactive use w/o flag" width="300"/>

---

### 2. Non-Interactive Mode (CLI)
Use the -t or --target flag to submit the IOC directly via the command line.

python3 main.py -t <IOC_To_Analyze>

#### Example using Kali Linux:

python3 main.py -t 222.222.222.222

<img src="images/Non-Interactive_Terminal.png" alt="Non-Interactive with terminal output" width="300"/>

---

### 3. Generate Report (Does not support HTML or CSV formats yet)
Use the -r or --report flag to write the analysis result to a specified file. This can be combined with -t. The report will be written in append mode.

python3 main.py -r <Report_file.txt>

python3 main.py -r <Report_file.txt> -t <IOC_To_Analyze>

#### Example when run interactively:

<img src="images/Interactive_Report-file.png" alt="Interactive with report file output" width="300"/>

#### Example when run non-interactively combined with report flag (cached result):

<img src="images/Non-Interactive_Report-file.png" alt="Non-Interactive with report file output" width="300"/>

---

### Test run of v1.0.0 @youtube

<div align="center">
  <iframe width="480" height="270" src="https://www.youtube.com/embed/ZMp0mXDKUuo?si=Lr-m2ub8cg7W3fuQ" frameborder="0" allowfullscreen></iframe>
</div>

<small>[To the top](#ioc-analyzer)</small>
---

## Project Structure

#### To clearly illustrate where files are located, the project follows this structure:

```markdown
IOC_Analyzer/
├── main.py             <-- Application Entry Point
├── requirements.txt    <-- Required libraries
├── .env                <-- dotenv-file containing API-keys
├── ioc_analyzer.log    <-- Log file created here upon first use of script
├── ioc_cache.json      <-- Cache file created and maintained here upon use of script
├── <Report_File>       <-- Report file created and appended here upon use of -r flag.
└── modules/
    ├── virustotal.py:  Contains classes and methods for making API calls to VirusTotal.
    ├── abuseipdb.py:   Contains classes and methods for making API calls to AbuseIPDB.
    ├── ipinfo.py:      Contains classes and methods for making API calls to IPinfo.
    ├── cache.py:       Manages the local caching of results in `ioc_cache.json`.
    ├── formatter.py:   Responsible for taking raw results and formatting them into readable output.
    ├── pre_checks.py:  Handles initial validation (e.g., checking API keys and IOC type).
    ├── reporter.py:    Handles writing analysis output to the log file (`ioc_analyzer.log`) or a specified report file.
    ├── logger.py:      Configures and manages the Python logging module, consistently written to the `ioc_analyzer.log` file.
    └── utils.py:       Contains utility functions used across multiple modules, primarily for input validation and classification.
```

<small>[To the top](#ioc-analyzer)</small>
---

## Security Note

* **API Keys:** Ensure your `.env` file containing API keys is never committed or pushed to a public repository. It is included in the `.gitignore` file for your safety.
* **IOCs:** Exercise caution when submitting active Indicators of Compromise (URLs, IPs) to external services.

<small>[To the top](#ioc-analyzer)</small>
---

## Contributing

I gladly welcome contributions and ideas! If you have suggestions or want to report a bug, please follow these steps:

1.  Fork the repository.
2.  Create a new feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

<small>[To the top](#ioc-analyzer)</small>
---
