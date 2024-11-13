# BurpScanner

## Overview

**BurpScanner** is a custom Burp Suite extension designed to integrate the powerful Nuclei scanner directly into Burp Suite. This tool enables users to perform vulnerability scans with Nuclei while leveraging Burp Suite's interface and functionality.

## Features

- **Nuclei Integration**: Run Nuclei scans directly within Burp Suite.
- **Customizable Commands**: Modify scan parameters, severity levels, and additional Nuclei options.
- **Real-Time Results**: View scan results live in Burp Suite's UI.
- **Context Menu Integration**: Send requests directly to BurpScanner from the Burp Suite interface.
- **Configuration Management**: Automatically load and save Nuclei paths and settings.
- **Result Export**: Supports JSON output for further analysis.
- **Custom Scan Issues**: Automatically create Burp Suite issues based on Nuclei findings.

## Requirements

- Burp Suite (Community or Professional)
- [Nuclei](https://github.com/projectdiscovery/nuclei) binary installed and accessible.

## Installation

1. Ensure Burp Suite and Nuclei are installed.
2. Clone or download the BurpScanner extension.
3. Open Burp Suite, go to the "Extender" tab, and add the `.py` script as an extension.
4. Once loaded, the **BurpScanner** tab will appear in Burp Suite.

## Usage

### Initial Configuration

1. Open the **BurpScanner** tab.
2. Specify the paths for the Nuclei binary and templates directory.
3. Customize the scan parameters using the provided fields and checkboxes.
4. Use the command preview area to verify or modify the generated Nuclei command.

### Running a Scan

1. Enter the target URL in the "Target URL" field.
2. Click **Start Scan** to begin scanning.
3. View live results in the "Scan Results" panel.
4. To stop the scan, click **Stop Scan**.

### Sending Requests to BurpScanner

1. Right-click a request in Burp Suite.
2. Select **Send to BurpScanner**.
3. The request's URL and headers will be populated in the BurpScanner UI.

## Options and Parameters

- **Target URL**: Specify the target URL for the scan.
- **Nuclei Path**: Path to the Nuclei binary.
- **Templates Path**: Directory containing Nuclei templates.
- **Custom Arguments**: Additional command-line arguments for Nuclei.
- **Severity**: Filter vulnerabilities by severity level.
- **Rate Limit**: Limit the number of requests per second.
- **Concurrency**: Number of concurrent threads.
- **Proxy**: Use a proxy for Nuclei scans.
- **JSON Output**: Enable JSON output for results.

## Custom Scan Issues

Nuclei findings are automatically converted into Burp Suite scan issues, providing the following details:

- **Issue Name**
- **Severity**
- **Confidence**
- **Detailed Findings**

## Saving and Loading Configuration

Settings such as Nuclei paths, templates, and custom arguments are automatically saved and reloaded upon restarting Burp Suite.

## Known Issues

- The extension may encounter issues if the Nuclei binary is not properly configured or accessible.
- Ensure the Nuclei templates directory is up-to-date for accurate scanning.

## Contributing

Contributions are welcome! If you encounter bugs or have feature requests, feel free to open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Unauthorized use is prohibited.
