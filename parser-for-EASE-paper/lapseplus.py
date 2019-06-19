import plugincommon

class LapsePlusSpecific():
    PLUGIN_LOG_FILENAME = 'lapseplus.log'
    PLUGIN_OUTPUT_FILENAME = 'lapseplus.csv'
    PLUGIN_SPLIT_DELIMITER = '\t;\t'
    PLUGIN_LINEARR_FILENAME_INDEX = 4
    PLUGIN_LINEARR_METHOD_INDEX = 1
    PLUGIN_LINEARR_TYPE_INDEX = 2

    correct_categories = {
        # Injection
        'CWE78': ['Command Injection'],
        'CWE89': ['SQL Injection'],
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
        'CWE566': ['Parameter Tampering'],
        # Security Misconfiguration
        'CWE395': [],
        'CWE396': [],
        'CWE397': [],
        # Cross-site scripting
        'CWE80': ['Cross-site Scripting'],
        'CWE81': ['Cross-site Scripting'],
        'CWE83': ['Cross-site Scripting'],
    }

    def __init__(self, plugin_common):
        self.plugin_common = plugin_common

    def process_log_line(self, line):
        linesplit = line.split(self.PLUGIN_SPLIT_DELIMITER)
        if (len(linesplit) != 6):
            return
        filename = linesplit[self.PLUGIN_LINEARR_FILENAME_INDEX].strip()
        if (not filename.startswith('CWE')):
            return
        cwe = plugin_common.get_cwe_from_filename(filename)
        method = linesplit[self.PLUGIN_LINEARR_METHOD_INDEX].strip()
        vultype = linesplit[self.PLUGIN_LINEARR_TYPE_INDEX].strip()
        correct_vultype = vultype in self.correct_categories[cwe]
        plugin_common.add_detection(filename, cwe, method, vultype, correct_vultype)

plugin_common = plugincommon.PluginCommon()
plugin_specific = LapsePlusSpecific(plugin_common)

with open(plugin_specific.PLUGIN_LOG_FILENAME, 'r') as f:
    for line in f:
        plugin_specific.process_log_line(line)

plugin_common.write_output(plugin_specific.PLUGIN_OUTPUT_FILENAME)
plugin_common.print_detections()