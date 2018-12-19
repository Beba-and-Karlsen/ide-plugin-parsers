import plugincommon
import re

class ESVDSpecific():
    PLUGIN_LOG_FILENAME = 'esvd.log'
    PLUGIN_OUTPUT_FILENAME = 'esvd.csv'
    PLUGIN_SPLIT_DELIMITER = '\t'
    PLUGIN_LINEARR_FILENAME_INDEX = 4
    PLUGIN_LINEARR_METHOD_INDEX = -1
    PLUGIN_LINEARR_TYPE_INDEX = 3

    ESVD_LINEARR_METHOD_SPLIT_DELIMITER = ' - '
    ESVD_LINEARR_METHOD_INDEX = 5

    correct_categories = {
        # Injection
        'CWE78': ['Command Injection'],
        'CWE89': ['Sql Injection'],
        'CWE90': ['LDAP Injection'],
        'CWE113': ['HTTP Response Splitting'],
        'CWE134': [],
        'CWE643': ['XPath Injection'],
        # Broken auth
        'CWE256': [],
        'CWE259': [],
        'CWE321': [],
        'CWE523': [],
        'CWE549': [],
        # Sensitive data exposure
        'CWE315': [],
        'CWE319': [],
        'CWE325': [],
        'CWE327': [],
        'CWE328': [],
        'CWE329': [],
        'CWE614': [],
        'CWE759': [],
        'CWE760': [],
        # Broken Access Control
        'CWE23': ['Path Traversal'],
        'CWE36': ['Path Traversal'],
        'CWE566': [],
        # Security Misconfiguration
        'CWE395': ['Security Misconfiguration'],
        'CWE396': ['Security Misconfiguration'],
        'CWE397': ['Security Misconfiguration'],
        # Cross-site scripting
        'CWE80': ['Cross-Site Scripting'],
        'CWE81': ['Cross-Site Scripting'],
        'CWE83': ['Cross-Site Scripting'],
    }

    def __init__(self, plugin_common):
        self.plugin_common = plugin_common

    def process_log_line(self, line):
        if (line.startswith('Description\tPriority') or len(line) < 7):
            return
        linesplit = line.split(self.PLUGIN_SPLIT_DELIMITER)
        filename = linesplit[self.PLUGIN_LINEARR_FILENAME_INDEX].strip()
        if (not filename.startswith('CWE')):
            return
        cwe = plugin_common.get_cwe_from_filename(filename)
        methodsplit = linesplit[self.ESVD_LINEARR_METHOD_INDEX].split(self.ESVD_LINEARR_METHOD_SPLIT_DELIMITER)
        method = methodsplit[0].strip()
        if (len(methodsplit) > 3):
            if (methodsplit[1].startswith('good') or methodsplit[1].startswith('bad')):
                method = re.sub('(\(([a-zA-Z0-9,]*)\))', '', methodsplit[1].strip()).strip()
        vultype = linesplit[self.PLUGIN_LINEARR_TYPE_INDEX].strip()
        correct_vultype = vultype in self.correct_categories[cwe]
        plugin_common.add_detection(filename, cwe, method, vultype, correct_vultype)


plugin_common = plugincommon.PluginCommon()
plugin_specific = ESVDSpecific(plugin_common)

with open(plugin_specific.PLUGIN_LOG_FILENAME, 'r') as f:
    for line in f:
        plugin_specific.process_log_line(line)

plugin_common.write_output(plugin_specific.PLUGIN_OUTPUT_FILENAME)
plugin_common.print_detections()