import plugincommon
import os
import sys
import untangle

class SpotBugsSpecific():
    PLUGIN_OUTPUT_FILENAME = 'parser_report.csv'

    correct_categories = {

        #                         #
        #  1   I N J E C T I O N  #
        #                         #

        # OS Command Injection
        'CWE78': ['COMMAND_INJECTION','SCALA_COMMAND_INJECTION'],
        # SQL Injection
        'CWE89': ['SQL','CUSTOM_INJECTION','SQL_INJECTION','SQL_INJECTION_TURBINE','SQL_INJECTION_HIBERNATE',
                'SQL_INJECTION_JDO','SQL_INJECTION_JPA','SQL_INJECTION_SPRING_JDBC','SQL_INJECTION_JDBC',
                'SCALA_SQL_INJECTION_SLICK','SCALA_SQL_INJECTION_ANORM','SQL_INJECTION_ANDROID'],
        # LDAP Injection
        'CWE90': ['LDAP_INJECTION'],
        # HTTP Response Splitting
        'CWE113': ['HRS','HTTP_RESPONSE_SPLITTING'],
        # Use of Externally-Controlled Format String
        'CWE134': ['FORMAT_STRING_MANIPULATION'],
        # XPath Injection
        'CWE643': ['XPATH_INJECTION'],

        #                                                 #
        #  2   B R O K E N   A U T H E N T I C A T I O N  #
        #                                                 #

        # Unprotected Storage of Credentials
        'CWE256': [],
        # Use of Hard-coded Password
        'CWE259': ['DMI_CONSTANT_DB_PASSWORD','HARD_CODE_PASSWORD'],
        # Use of Hard-coded Cryptographic Key
        'CWE321': ['HARD_CODE_KEY'],
        # Unprotected Transport of Credentials
        'CWE523': [],
        # Missing Password Field Masking
        'CWE549': [],

        #                                                     #
        #  3   S E N S I T I V E   D A T A   E X P O S U R E  #
        #                                                     #

        # Cleartext Storage of Sensitive Information in a Cookie
        'CWE315': ['COOKIE_USAGE'],
        # Cleartext Transmission of Sensitive Information
        'CWE319': ['UNENCRYPTED_SOCKET', 'UNENCRYPTED_SERVER_SOCKET'],
        # Missing Required Cryptographic Step
        'CWE325': [],
        # Use of a Broken or Risky Cryptographic Algorithm
        'CWE327': ['WEAK_MESSAGE_DIGEST_MD5','WEAK_MESSAGE_DIGEST_SHA1','CUSTOM_MESSAGE_DIGEST','NULL_CIPHER',
                'DES_USAGE','TDES_USAGE'],
        # Reversible One-Way Hash
        'CWE328': ['WEAK_MESSAGE_DIGEST_MD5','WEAK_MESSAGE_DIGEST_SHA1'],
        # Not Using a Random IV with CBC Mode
        'CWE329': ['STATIC_IV'],
        # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
        'CWE614': ['INSECURE_COOKIE'],
        # Use of a One-Way Hash without a Salt
        'CWE759': [],
        # Use of a One-Way Hash with a Predictable Salt
        'CWE760': [],

        #                                                 #
        #  5   B R O K E N   A C C E S S   C O N T R O L  #
        #                                                 #

        # Relative Path Traversal
        'CWE23': ['PT_RELATIVE_PATH_TRAVERSAL','PATH_TRAVERSAL_IN','PATH_TRAVERSAL_OUT'],
        # Absolute Path Traversal
        'CWE36': ['PT_ABSOLUTE_PATH_TRAVERSAL','PATH_TRAVERSAL_IN','PATH_TRAVERSAL_OUT'],
        # Authorization Bypass Through User-Controlled SQL Primary Key
        'CWE566': [],

        #                                                         #
        #  6   S E C U R I T Y   M I S C O N F I G U R A T I O N  #
        #                                                         #

        # Use of NullPointerException Catch to Detect NULL Pointer Deference
        'CWE395': [],
        # Declaration of Catch for Generic Exception
        'CWE396': [],
        # Declaration of Throws for Generic Exception
        'CWE397': [],

        #                                                           #
        #  7   C R O S S - S I T E   S C R I P T I N G   ( X S S )  #
        #                                                           #

        # Basic XSS
        'CWE80': ['XSS','XSS_REQUEST_WRAPPER','JSP_JSTL_OUT','XSS_JSP_PRINT','XSS_SERVLET',
                'ANDROID_WEB_VIEW_JAVASCRIPT','SCALA_XSS_TWIRL','SCALA_XSS_MVC_API'],
        # Improper Neutralization of Script in an Error Message
        'CWE81': ['XSS','XSS_REQUEST_WRAPPER','JSP_JSTL_OUT','XSS_JSP_PRINT','XSS_SERVLET',
                'ANDROID_WEB_VIEW_JAVASCRIPT','SCALA_XSS_TWIRL','SCALA_XSS_MVC_API'],
        # Improper Neutralization of Script in Attributes in a Web Page
        'CWE83': ['XSS','XSS_REQUEST_WRAPPER','JSP_JSTL_OUT','XSS_JSP_PRINT','XSS_SERVLET',
                'ANDROID_WEB_VIEW_JAVASCRIPT','SCALA_XSS_TWIRL','SCALA_XSS_MVC_API']
    }

    def __init__(self, plugin_common):
        self.plugin_common = plugin_common
    
    def process_xml_file(self, xml_file):
        # Report of all vulnerabilities from the .xml file.
        try:
            report = untangle.parse(xml_file)
        except:
            print('%s is not a recognized SpotBugs report file.' % xml_file)
            sys.exit(2)
        # Complete list of all vulnerabilities reported from the .xml file.
        vuln_list = report.BugCollection.BugInstance
        # Iterates through all vulnerabilities reported.
        for vuln in vuln_list:
            filename = vuln.Class.SourceLine['sourcefile']
            # The bug is reported in a support class.
            if (not filename.startswith('CWE')): break
            # Retrieves the CWE ID.
            cwe = plugin_common.get_cwe_from_filename(filename)
            # Retrieves the vulnerability category and type.
            category = vuln['abbrev']
            vultype = vuln['type']
            correct_vultype = category in self.correct_categories[cwe] or vultype in self.correct_categories[cwe]
            category_and_vultype = '%s (%s)' % (vultype, category)
            # Retrieves the method the vulnerability is called in.
            method = 'N/A'
            if 'Method' in dir(vuln):
                # Handles the fact that vuln.Method can be both None, one item or multiple items.
                methods = []
                methods.extend(vuln.Method)
                method = methods[0]['name']
            elif 'Field' in dir(vuln): method = vuln.Field['name']
            # Appends the bug object to the list of bugs.
            plugin_common.add_detection(filename, cwe, method, category_and_vultype, correct_vultype)

plugin_common = plugincommon.PluginCommon()
plugin_specific = SpotBugsSpecific(plugin_common)

xml_folder = sys.argv[1]
for file in os.listdir(xml_folder):
    if file.endswith('.xml'):
        plugin_specific.process_xml_file(os.path.join(xml_folder, file))

plugin_common.write_output(xml_folder + plugin_specific.PLUGIN_OUTPUT_FILENAME)
plugin_common.print_detections()