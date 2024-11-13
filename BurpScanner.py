try:
    from burp import IBurpExtender, ITab, IScanIssue, IContextMenuFactory, IExtensionStateListener
    from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension, Color, EventQueue
    from javax.swing import (JPanel, JLabel, JButton, JTextField, JTextArea, JScrollPane, JOptionPane, JFileChooser,
                             JMenuItem, JCheckBox, JSplitPane, JSeparator, SwingConstants, JComboBox)
    from javax.swing.border import EmptyBorder, TitledBorder
    from javax.swing.event import DocumentListener
    from java.net import URL
    from java.util import ArrayList
    from threading import Thread
    import subprocess
    import json
    import os
    import sys
    import re

except ImportError as e:
    print(e)

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._callbacks.setExtensionName("BurpScanner")
        self._helpers = callbacks.getHelpers()

        # Initialize User Interface
        self.initUI()

        # Register extension state listener and context menu factory
        self._callbacks.registerExtensionStateListener(self)
        self._callbacks.registerContextMenuFactory(self)

        # Load saved settings or perform automatic path detection
        self.loadConfig()

        # Initialize variables
        self.isScanning = False
        self.scanThreads = []
        self.runningSubprocesses = set()

        print("Nuclei extension loaded successfully.")

    def initUI(self):
        # Main panel
        self.mainPanel = JPanel(BorderLayout(10, 10))
        self.mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Split pane to separate options and results
        self.splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.splitPane.setResizeWeight(0.5)
        self.mainPanel.add(self.splitPane, BorderLayout.CENTER)

        # Upper panel for options
        self.optionsPanel = JPanel(GridBagLayout())
        self.optionsPanel.setBorder(TitledBorder("Scan Options"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.anchor = GridBagConstraints.NORTHWEST

        # Target URL field
        gbc.gridx = 0
        gbc.gridy = 0
        self.optionsPanel.add(JLabel("Target URL:"), gbc)
        gbc.gridx = 1
        gbc.weightx = 1.0
        self.targetField = JTextField('', 30)
        self.targetField.setToolTipText("Enter the target URL to scan")
        self.targetField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.targetField, gbc)
        gbc.weightx = 0
        gbc.gridx = 2
        self.scanButton = JButton("Start Scan", actionPerformed=self.startScan)
        self.optionsPanel.add(self.scanButton, gbc)
        gbc.gridx = 3
        self.stopButton = JButton("Stop Scan", actionPerformed=self.stopScan)
        self.stopButton.setEnabled(False)
        self.optionsPanel.add(self.stopButton, gbc)

        # Separator
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 4
        self.optionsPanel.add(JSeparator(SwingConstants.HORIZONTAL), gbc)
        gbc.gridwidth = 1

        # Nuclei binary path
        gbc.gridx = 0
        gbc.gridy = 2
        self.optionsPanel.add(JLabel("Nuclei Path:"), gbc)
        gbc.gridx = 1
        self.nucleiPathField = JTextField('', 30)
        self.nucleiPathField.setToolTipText("Path to the Nuclei binary")
        self.nucleiPathField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.nucleiPathField, gbc)
        gbc.gridx = 2
        self.browseNucleiButton = JButton("Browse", actionPerformed=self.browseNucleiPath)
        self.optionsPanel.add(self.browseNucleiButton, gbc)

        # Templates path
        gbc.gridx = 0
        gbc.gridy = 3
        self.optionsPanel.add(JLabel("Templates Path:"), gbc)
        gbc.gridx = 1
        self.templatesPathField = JTextField('', 30)
        self.templatesPathField.setToolTipText("Path to the Nuclei templates directory")
        self.templatesPathField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.templatesPathField, gbc)
        gbc.gridx = 2
        self.browseTemplatesButton = JButton("Browse", actionPerformed=self.browseTemplatesPath)
        self.optionsPanel.add(self.browseTemplatesButton, gbc)

        # Custom arguments
        gbc.gridx = 0
        gbc.gridy = 4
        self.optionsPanel.add(JLabel("Custom Arguments:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.customArgsField = JTextField('', 30)
        self.customArgsField.setToolTipText("Additional Nuclei command-line arguments")
        self.customArgsField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.customArgsField, gbc)
        gbc.gridwidth = 1

        # Severity Dropdown
        gbc.gridx = 0
        gbc.gridy = 5
        self.optionsPanel.add(JLabel("Severity (-severity):"), gbc)
        gbc.gridx = 1
        self.severityOptions = ["", "low", "medium", "high", "critical"]
        self.severityDropdown = JComboBox(self.severityOptions)
        self.severityDropdown.setToolTipText("Select severity levels to include")
        self.severityDropdown.addActionListener(self.updateCommandPreview)
        self.optionsPanel.add(self.severityDropdown, gbc)

        # Proxy
        gbc.gridx = 0
        gbc.gridy = 6
        self.optionsPanel.add(JLabel("Proxy (-proxy):"), gbc)
        gbc.gridx = 1
        self.proxyField = JTextField('', 30)
        self.proxyField.setToolTipText("Proxy server (e.g., socks5://127.0.0.1:8080)")
        self.proxyField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.proxyField, gbc)

        # Checkboxes for options
        gbc.gridx = 0
        gbc.gridy = 7
        self.newTemplatesCheckbox = JCheckBox("Run only New Templates")
        self.newTemplatesCheckbox.setToolTipText("Include only latest released templates in the scan")
        self.newTemplatesCheckbox.addActionListener(self.updateCommandPreview)
        self.optionsPanel.add(self.newTemplatesCheckbox, gbc)

        gbc.gridx = 1
        self.autoScanCheckbox = JCheckBox("Tech Detection Automatic Scan")
        self.autoScanCheckbox.setToolTipText("Enable automatic scanning with Wappalyzer")
        self.autoScanCheckbox.addActionListener(self.updateCommandPreview)
        self.optionsPanel.add(self.autoScanCheckbox, gbc)

        # Rate Limit (-rl)
        gbc.gridx = 0
        gbc.gridy = 8
        self.optionsPanel.add(JLabel("Rate Limit:"), gbc)
        gbc.gridx = 1
        self.rateLimitField = JTextField('', 10)
        self.rateLimitField.setToolTipText("Maximum requests per second")
        self.rateLimitField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.rateLimitField, gbc)

        # Concurrency (-c)
        gbc.gridx = 0
        gbc.gridy = 9
        self.optionsPanel.add(JLabel("Concurrency:"), gbc)
        gbc.gridx = 1
        self.concurrencyField = JTextField('', 10)
        self.concurrencyField.setToolTipText("Number of concurrent threads")
        self.concurrencyField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.concurrencyField, gbc)

        # Tags (-tags)
        gbc.gridx = 0
        gbc.gridy = 10
        self.optionsPanel.add(JLabel("Tags:"), gbc)
        gbc.gridx = 1
        self.tagsField = JTextField('', 30)
        self.tagsField.setToolTipText("Comma-separated list of template tags to include")
        self.tagsField.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        self.optionsPanel.add(self.tagsField, gbc)

        # Headers (-H)
        gbc.gridx = 0
        gbc.gridy = 11
        self.optionsPanel.add(JLabel("Headers"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.headersArea = JTextArea(5, 30)
        self.headersArea.setLineWrap(True)
        self.headersArea.setWrapStyleWord(True)
        self.headersArea.setToolTipText("Custom headers to include in the scan")
        self.headersArea.getDocument().addDocumentListener(FieldListener(self.updateCommandPreview))
        headersScrollPane = JScrollPane(self.headersArea)
        self.optionsPanel.add(headersScrollPane, gbc)
        gbc.gridwidth = 1

        # JSON Output Checkbox
        gbc.gridx = 0
        gbc.gridy = 12
        self.jsonOutputCheckbox = JCheckBox("Enable JSON Output (-json)")
        self.jsonOutputCheckbox.setToolTipText("Include the -json flag to enable JSON output for parsing findings")
        self.jsonOutputCheckbox.addActionListener(self.updateCommandPreview)
        self.optionsPanel.add(self.jsonOutputCheckbox, gbc)

        # Command Preview Area (now editable) and Reset Button
        gbc.gridx = 0
        gbc.gridy = 13
        gbc.gridwidth = 3
        self.optionsPanel.add(JSeparator(SwingConstants.HORIZONTAL), gbc)
        gbc.gridwidth = 1

        gbc.gridx = 0
        gbc.gridy = 14
        self.optionsPanel.add(JLabel("Command:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        self.commandPreviewArea = JTextArea(3, 50)
        self.commandPreviewArea.setLineWrap(True)
        self.commandPreviewArea.setWrapStyleWord(True)
        self.commandPreviewArea.setToolTipText("Modify the command as needed")
        commandScrollPane = JScrollPane(self.commandPreviewArea)
        self.optionsPanel.add(commandScrollPane, gbc)
        self.commandPreviewArea.getDocument().addDocumentListener(FieldListener(self.commandEdited))
        gbc.gridwidth = 1

        gbc.gridx = 3
        self.resetButton = JButton("Reset Command", actionPerformed=self.resetCommand)
        self.optionsPanel.add(self.resetButton, gbc)

        # Lower panel for results
        self.resultsPanel = JPanel(BorderLayout())
        self.resultsPanel.setBorder(TitledBorder("Scan Results"))

        # Results area with real-time output
        self.resultsArea = JTextArea()
        self.resultsArea.setEditable(False)
        self.resultsArea.setLineWrap(True)
        self.resultsArea.setWrapStyleWord(True)
        resultsScrollPane = JScrollPane(self.resultsArea)
        self.resultsPanel.add(resultsScrollPane, BorderLayout.CENTER)

        # Add panels to split pane
        self.splitPane.setTopComponent(self.optionsPanel)
        self.splitPane.setBottomComponent(self.resultsPanel)

        # Add main panel to Burp
        self._callbacks.addSuiteTab(self)

        # Initial command preview
        self.updateCommandPreview()

    def getTabCaption(self):
        return "BurpScanner"

    def getUiComponent(self):
        return self.mainPanel

    def loadConfig(self):
        # Automatic path detection for Nuclei binary
        nuclei_paths = [
            '/usr/bin/nuclei',
            '/usr/local/bin/nuclei',
            os.path.expanduser('~/go/bin/nuclei'),
            os.path.expanduser('~/.pdtm/go/bin/nuclei')
        ]
        found_nuclei = False
        for path in nuclei_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                self.nucleiPathField.setText(path)
                found_nuclei = True
                break
        if not found_nuclei:
            saved_path = self._callbacks.loadExtensionSetting("nucleiPath")
            if saved_path:
                self.nucleiPathField.setText(saved_path)

        # Automatic path detection for Nuclei templates
        templates_path = os.path.expanduser('~/nuclei-templates')
        if os.path.isdir(templates_path):
            self.templatesPathField.setText(templates_path)
        else:
            saved_templates = self._callbacks.loadExtensionSetting("templatesPath")
            if saved_templates:
                self.templatesPathField.setText(saved_templates)

        # Load other settings
        if self._callbacks.loadExtensionSetting("customArgs"):
            self.customArgsField.setText(self._callbacks.loadExtensionSetting("customArgs"))
        if self._callbacks.loadExtensionSetting("proxy"):
            self.proxyField.setText(self._callbacks.loadExtensionSetting("proxy"))
        if self._callbacks.loadExtensionSetting("rateLimit"):
            self.rateLimitField.setText(self._callbacks.loadExtensionSetting("rateLimit"))
        if self._callbacks.loadExtensionSetting("concurrency"):
            self.concurrencyField.setText(self._callbacks.loadExtensionSetting("concurrency"))
        if self._callbacks.loadExtensionSetting("tags"):
            self.tagsField.setText(self._callbacks.loadExtensionSetting("tags"))
        if self._callbacks.loadExtensionSetting("headers"):
            self.headersArea.setText(self._callbacks.loadExtensionSetting("headers"))
        if self._callbacks.loadExtensionSetting("newTemplates"):
            self.newTemplatesCheckbox.setSelected(self._callbacks.loadExtensionSetting("newTemplates") == 'True')
        if self._callbacks.loadExtensionSetting("autoScan"):
            self.autoScanCheckbox.setSelected(self._callbacks.loadExtensionSetting("autoScan") == 'True')
        if self._callbacks.loadExtensionSetting("severity"):
            self.severityDropdown.setSelectedItem(self._callbacks.loadExtensionSetting("severity"))
        if self._callbacks.loadExtensionSetting("jsonOutput"):
            self.jsonOutputCheckbox.setSelected(self._callbacks.loadExtensionSetting("jsonOutput") == 'True')
        # Load the last used command if available
        if self._callbacks.loadExtensionSetting("lastCommand"):
            self.commandPreviewArea.setText(self._callbacks.loadExtensionSetting("lastCommand"))

    def saveConfig(self):
        self._callbacks.saveExtensionSetting("nucleiPath", self.nucleiPathField.getText())
        self._callbacks.saveExtensionSetting("templatesPath", self.templatesPathField.getText())
        self._callbacks.saveExtensionSetting("customArgs", self.customArgsField.getText())
        self._callbacks.saveExtensionSetting("proxy", self.proxyField.getText())
        self._callbacks.saveExtensionSetting("rateLimit", self.rateLimitField.getText())
        self._callbacks.saveExtensionSetting("concurrency", self.concurrencyField.getText())
        self._callbacks.saveExtensionSetting("tags", self.tagsField.getText())
        self._callbacks.saveExtensionSetting("headers", self.headersArea.getText())
        self._callbacks.saveExtensionSetting("newTemplates", str(self.newTemplatesCheckbox.isSelected()))
        self._callbacks.saveExtensionSetting("autoScan", str(self.autoScanCheckbox.isSelected()))
        self._callbacks.saveExtensionSetting("severity", self.severityDropdown.getSelectedItem())
        self._callbacks.saveExtensionSetting("jsonOutput", str(self.jsonOutputCheckbox.isSelected()))
        # Save the last used command
        self._callbacks.saveExtensionSetting("lastCommand", self.commandPreviewArea.getText())

    def extensionUnloaded(self):
        self.saveConfig()
        self.stopAllScans()
        print("Nuclei extension unloaded.")

    def startScan(self, event):
        target = self.targetField.getText().strip()
        if not target:
            JOptionPane.showMessageDialog(self.mainPanel, "Please enter a target URL.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        # Ensure nuclei path is set
        nuclei_path = self.nucleiPathField.getText().strip()
        if not nuclei_path or not os.path.isfile(nuclei_path) or not os.access(nuclei_path, os.X_OK):
            JOptionPane.showMessageDialog(self.mainPanel, "Invalid Nuclei path.", "Error", JOptionPane.ERROR_MESSAGE)
            return

        self.isScanning = True
        self.scanButton.setEnabled(False)
        self.stopButton.setEnabled(True)
        self.resultsArea.setText("")

        # Use the command from the command preview area
        cmd = self.commandPreviewArea.getText().strip()
        if not cmd:
            JOptionPane.showMessageDialog(self.mainPanel, "Command is empty. Please specify a command.", "Error", JOptionPane.ERROR_MESSAGE)
            self.isScanning = False
            self.scanButton.setEnabled(True)
            self.stopButton.setEnabled(False)
            return

        cmd = cmd.replace('{target}', target)
        cmd_list = cmd.split()

        scanThread = Thread(target=self.runNucleiScan, args=(cmd_list,))
        scanThread.start()
        self.scanThreads.append(scanThread)

    def stopScan(self, event):
        self.stopAllScans()

    def stopAllScans(self):
        for p in list(self.runningSubprocesses):
            p.terminate()
            self.runningSubprocesses.remove(p)
        self.isScanning = False
        self.scanButton.setEnabled(True)
        self.stopButton.setEnabled(False)

    def runNucleiScan(self, cmd):
        self.appendResult("Starting scan...\n")
        # Display the executed command
        self.appendResult("Executed command: {}\n".format(' '.join(cmd)))

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True)
            self.runningSubprocesses.add(process)

            ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

            for line in iter(process.stdout.readline, ''):
                if not self.isScanning:
                    break
                line_clean = ansi_escape.sub('', line)  # Remove ANSI escape sequences
                self.appendResult(line_clean)
                self.handleNucleiResult(line_clean.strip())

            process.stdout.close()
            process.wait()
            self.runningSubprocesses.remove(process)

            if self.isScanning:
                self.appendResult("\nScan completed.\n")
            else:
                self.appendResult("\nScan stopped.\n")

        except Exception as e:
            self.appendResult("Error during scan: {}\n".format(str(e)))
        finally:
            self.isScanning = False
            self.scanButton.setEnabled(True)
            self.stopButton.setEnabled(False)

    def handleNucleiResult(self, result):
        try:
            finding = json.loads(result)
            info = finding.get('info', {})
            name = info.get('name', 'Nuclei Detection')
            severity = info.get('severity', 'Information').capitalize()
            description = info.get('description', '')
            matched_at = finding.get('matched-at', '')
            template_id = finding.get('template-id', '')
            reference = info.get('reference', [])
            vuln_tags = info.get('tags', '')

            detail = "Template ID: {}\n".format(template_id)
            detail += "Matched at: {}\n".format(matched_at)
            if vuln_tags:
                detail += "Tags: {}\n".format(vuln_tags)
            if description:
                detail += "Description: {}\n".format(description)
            if reference:
                detail += "References:\n"
                for ref in reference:
                    detail += "- {}\n".format(ref)

            self.appendResult("\n[{}] {}\n{}\n".format(severity, name, detail))

            # Create an issue in Burp
            url = URL(matched_at)
            protocol = url.getProtocol()
            host = url.getHost()
            port = url.getPort() if url.getPort() != -1 else (443 if protocol == 'https' else 80)
            is_https = protocol == 'https'

            httpService = self._helpers.buildHttpService(host, port, is_https)
            request = self._helpers.buildHttpRequest(url)

            # Set headers if any
            headers_text = self.headersArea.getText()
            if headers_text:
                headers = headers_text.strip().split('\n')
                headers = [header.strip() for header in headers]
                requestInfo = self._helpers.analyzeRequest(request)
                body = request[requestInfo.getBodyOffset():]
                headers_list = requestInfo.getHeaders()
                # Replace default headers with custom headers
                headers_list = [headers_list[0]] + headers
                request = self._helpers.buildHttpMessage(headers_list, body)

            httpMessages = [self._callbacks.makeHttpRequest(httpService, request)]

            issue = CustomScanIssue(
                httpService,
                url,
                httpMessages,
                name,
                detail.replace('\n', '<br>'),
                severity,
                'Certain'
            )

            self._callbacks.addScanIssue(issue)

        except ValueError:
            # Not a JSON result, ignore
            pass
        except Exception as e:
            self.appendResult("Error processing result: {}\n".format(str(e)))

    def appendResult(self, text):
        # Append text to the results area in a thread-safe manner
        def update():
            self.resultsArea.append(text)
            self.resultsArea.setCaretPosition(self.resultsArea.getDocument().getLength())

        EventQueue.invokeLater(update)

    def browseNucleiPath(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        ret = chooser.showOpenDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.nucleiPathField.setText(file.getAbsolutePath())
            self.updateCommandPreview()

    def browseTemplatesPath(self, event):
        chooser = JFileChooser()
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        ret = chooser.showOpenDialog(self.mainPanel)
        if ret == JFileChooser.APPROVE_OPTION:
            directory = chooser.getSelectedFile()
            self.templatesPathField.setText(directory.getAbsolutePath())
            self.updateCommandPreview()

    def createMenuItems(self, invocation):
        menu = []
        messages = invocation.getSelectedMessages()
        if messages:
            menuItem = JMenuItem("Send to BurpScanner", actionPerformed=lambda x, inv=invocation: self.sendToNuclei(inv))
            menu.append(menuItem)
        return menu

    def sendToNuclei(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            requestInfo = self._helpers.analyzeRequest(messages[0])
            url = requestInfo.getUrl()
            self.targetField.setText(str(url))

            # Automatically extract headers
            headers = requestInfo.getHeaders()
            headers_text = '\n'.join(headers[1:])  # Exclude the request line
            self.headersArea.setText(headers_text)

            self.updateCommandPreview()

    def updateCommandPreview(self, event=None):
        # Build the command based on current settings
        target = '{target}'
        cmd = [self.nucleiPathField.getText().strip() or 'nuclei', '-u', target]

        templates_path = self.templatesPathField.getText().strip()
        if templates_path:
            cmd.extend(['-t', templates_path])

        custom_args = self.customArgsField.getText().strip()
        if custom_args:
            cmd.extend(custom_args.split())

        # Add options based on checkboxes
        if self.newTemplatesCheckbox.isSelected():
            cmd.append('-nt')

        if self.autoScanCheckbox.isSelected():
            cmd.append('-as')

        # Severity
        severity = self.severityDropdown.getSelectedItem()
        if severity:
            cmd.extend(['-severity', severity])

        # Rate Limit
        rate_limit = self.rateLimitField.getText().strip()
        if rate_limit:
            cmd.extend(['-rl', rate_limit])

        # Concurrency
        concurrency = self.concurrencyField.getText().strip()
        if concurrency:
            cmd.extend(['-c', concurrency])

        # Tags
        tags = self.tagsField.getText().strip()
        if tags:
            cmd.extend(['-tags', tags])

        # Headers
        headers = self.headersArea.getText()
        if headers:
            header_lines = headers.strip().split('\n')
            for header in header_lines:
                cmd.extend(['-H', header.strip()])

        # JSON Output
        if self.jsonOutputCheckbox.isSelected():
            cmd.append('-json')

        # Proxy (must be added at the end)
        proxy = self.proxyField.getText().strip()
        if proxy:
            cmd.extend(['-proxy', proxy])

        # Update the command preview area
        self.commandPreviewArea.setText(' '.join(cmd))

    def commandEdited(self, event=None):
        # This method is called when the command preview area is edited
        pass  # No action needed unless you want to add validation

    def resetCommand(self, event):
        self.updateCommandPreview()

class FieldListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback

    def insertUpdate(self, event):
        self.callback()

    def removeUpdate(self, event):
        self.callback()

    def changedUpdate(self, event):
        self.callback()

class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
