import plugincommon

class AsideSpecific():
    PLUGIN_LOG_FILENAME = 'aside.log'
    PLUGIN_OUTPUT_FILENAME = 'aside.csv'
    PLUGIN_SPLIT_DELIMITER = '\t'
    PLUGIN_LINEARR_FILENAME_INDEX = 1
    PLUGIN_LINEARR_METHOD_INDEX = -1
    PLUGIN_LINEARR_TYPE_INDEX = -1

    ASIDE_LINEARR_METHODTYPE_SPLIT_DELIMITER = ':'
    ASIDE_LINEARR_METHODTYPE_INDEX = 0
    ASIDE_METHODTYPE_METHOD_INDEX = 1
    ASIDE_METHODTYPE_TYPE_INDEX = 2

    correct_categories = {
        # Injection
        'CWE78': ['input validation vulnerability'],
        'CWE89': ['input validation vulnerability'],
        'CWE90': ['input validation vulnerability'],
        'CWE113': ['input validation vulnerability'],
        'CWE134': ['input validation vulnerability'],
        'CWE643': ['input validation vulnerability'],
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
        'CWE23': ['input validation vulnerability'],
        'CWE36': ['input validation vulnerability'],
        'CWE566': ['input validation vulnerability'],
        # Security Misconfiguration
        'CWE395': [],
        'CWE396': [],
        'CWE397': [],
        # Cross-site scripting
        'CWE80': ['input validation vulnerability', 'output encoding vulnerability'],
        'CWE81': ['input validation vulnerability', 'output encoding vulnerability'],
        'CWE83': ['input validation vulnerability', 'output encoding vulnerability'],
    }

    def __init__(self, plugin_common):
        self.plugin_common = plugin_common

    def process_log_line(self, line):
        if (not line.startswith('ASIDE')):
            return
        linesplit = line.split(self.PLUGIN_SPLIT_DELIMITER)
        filename = linesplit[self.PLUGIN_LINEARR_FILENAME_INDEX].strip()
        if (not filename.startswith('CWE')):
            return
        cwe = plugin_common.get_cwe_from_filename(filename)
        methodtypesplit = linesplit[self.ASIDE_LINEARR_METHODTYPE_INDEX].split(self.ASIDE_LINEARR_METHODTYPE_SPLIT_DELIMITER)
        method = methodtypesplit[self.ASIDE_METHODTYPE_METHOD_INDEX].strip()
        vultype = methodtypesplit[self.ASIDE_METHODTYPE_TYPE_INDEX].strip()
        correct_vultype = vultype in self.correct_categories[cwe]
        plugin_common.add_detection(filename, cwe, method, vultype, correct_vultype)


plugin_common = plugincommon.PluginCommon()
plugin_specific = AsideSpecific(plugin_common)

with open(plugin_specific.PLUGIN_LOG_FILENAME, 'r') as f:
    for line in f:
        plugin_specific.process_log_line(line)

plugin_common.write_output(plugin_specific.PLUGIN_OUTPUT_FILENAME)
plugin_common.print_detections()