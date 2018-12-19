# Usage:
# Loop through all detections found by your plugin.
# Use the add_detection() method to add all detections, even if they are wrong
# Use the write_output() method to write the log file to a CSV file
# Use the print_detections() method to output the TP, FP counters to the console

import re

# Dictionary that includes number of test cases by CWE entry for Juliet Test Suite v1.2 and v1.3.
num_cases = {

    #                         #
    #  1   I N J E C T I O N  #
    #                         #
    
    'CWE78':   444, # OS Command Injection
    'CWE89':  2220, # SQL Injection
    'CWE90':   444, # LDAP Injection
    'CWE113': 1332, # HTTP Response Splitting
    'CWE134':  666, # Use of Externally-Controlled Format String
    'CWE643':  444, # XPath Injection

    #                                                 #
    #  2   B R O K E N   A U T H E N T I C A T I O N  #
    #                                                 #

    'CWE256':   37, # Unprotected Storage of Credentials
    'CWE259':  111, # Use of Hard-coded Password
    'CWE321':   37, # Use of Hard-coded Cryptographic Key
    'CWE523':   17, # Unprotected Transport of Credentials
    'CWE549':   17, # Missing Password Field Masking

    #                                                     #
    #  3   S E N S I T I V E   D A T A   E X P O S U R E  #
    #                                                     #

    'CWE315':   37, # Cleartext Storage of Sensitive Information in a Cookie
    'CWE319':  370, # Cleartext Transmission of Sensitive Information
    'CWE325':   34, # Missing Required Cryptographic Step
    'CWE327':   34, # Use of a Broken or Risky Cryptographic Algorithm
    'CWE328':   51, # Reversible One-Way Hash
    'CWE329':   17, # Not Using a Random IV with CBC Mode
    'CWE614':   17, # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    'CWE759':   17, # Use of a One-Way Hash without a Salt
    'CWE760':   17, # Use of a One-Way Hash with a Predictable Salt

    #                                                 #
    #  5   B R O K E N   A C C E S S   C O N T R O L  #
    #                                                 #

    'CWE23':   444, # Relative Path Traversal
    'CWE36':   444, # Absolute Path Traversal
    'CWE566':   37, # Authorization Bypass Through User-Controlled SQL Primary Key

    #                                                         #
    #  6   S E C U R I T Y   M I S C O N F I G U R A T I O N  #
    #                                                         #

    'CWE395':   17, # Use of NullPointerException Catch to Detect NULL Pointer Deference
    'CWE396':   34, # Declaration of Catch for Generic Exception
    'CWE397':    4, # Declaration of Throws for Generic Exception

    #                                                           #
    #  7   C R O S S - S I T E   S C R I P T I N G   ( X S S )  #
    #                                                           #

    'CWE80':   666, # Basic XSS
    'CWE81':   333, # Improper Neutralization of Script in an Error Message
    'CWE83':   333  # Improper Neutralization of Script in Attributes in a Web Page
}

class DetectionData:
    def __init__(self, cwe):
        self.cwe = cwe
        self.correctly_detected_vulnerabilities = {}
        self.wrong_detections_per_testcase = {}
        self.wrong_detections = 0
        self.unrelevant_detections = 0

    def getFalseNegatives(self):
        return num_cases[self.cwe] - len(self.correctly_detected_vulnerabilities.keys())

    def getRecall(self):
        divisor = num_cases[self.cwe]
        if (divisor == 0):
            return 0
        recall = len(self.correctly_detected_vulnerabilities.keys()) / divisor
        percentage = recall * 100
        return percentage

    def getPrecision(self):
        divisor = len(self.correctly_detected_vulnerabilities.keys()) + self.wrong_detections
        if (divisor == 0):
            return 0
        precision = len(self.correctly_detected_vulnerabilities.keys()) / divisor
        percentage = precision * 100
        return percentage

    def getDiscrimination(self):
        divisor = num_cases[self.cwe]
        if (divisor == 0):
            return 0
        discrimination_points = len(set(self.correctly_detected_vulnerabilities.keys()) - set(self.wrong_detections_per_testcase.keys()))
        discrimination_rate = discrimination_points / divisor
        percentage = discrimination_rate * 100
        return percentage


class PluginCommon:
    __output_buffer = ''
    __detections_by_cwe = {}

    # # Outputs the CSV file # #
    def write_output(self, filename):
        with open(filename, 'w') as f:
            f.writelines(self.__output_buffer)
        print('Detailed output written to %s' % filename)
    
    # # Add a detection, can be true positive, false positive, related, unrelated # #
    def add_detection(self, filename, cwe, method, vultype, correct_vultype):
        correct_place = self.__is_true_positive(method, filename)
        self.__add_output_line(cwe, method, vultype, correct_place, correct_vultype)
        if (correct_place and correct_vultype):
            self.__add_correct_detection(self.__strip_filename_of_endings(filename), cwe)
        elif (not correct_place and correct_vultype):
            self.__add_wrong_detection(self.__strip_filename_of_endings(filename), cwe)
        else:
            self.__add_unrelevant_detection(cwe)

    # # Outputs all stripped filenames with the amount of true positives to the console # #
    def print_correct_detections(self):
        for _, detection_data in self.__detections_by_cwe.items():
            for filename, count in detection_data.correctly_detected_vulnerabilities.items():
                print('%-60s\t%s (%s)' % (filename, 1, count))

    # # Outputs a table of CWE, TP, FP, Not relevant to the console # #
    def print_detections(self):
        print('Results:\n') #CWE, TP, FP, FN, Recall, Prec., Disc.%, Not relevant
        self.__print_detection_table_row('CWE', 'TP', 'FP', 'FN', 'Recall', 'Prec.', 'Disc.%', 'Not relevant')
        for cwe, detection_data in self.__detections_by_cwe.items():
            totalcorrect = len(detection_data.correctly_detected_vulnerabilities.keys())
            self.__print_detection_table_row(cwe, totalcorrect, detection_data.wrong_detections, detection_data.getFalseNegatives(), detection_data.getRecall(), detection_data.getPrecision(), detection_data.getDiscrimination(), detection_data.unrelevant_detections)

    # # Gets CWE code from Juliet filename # #
    def get_cwe_from_filename(self, filename):
        return filename.split('_')[0]
    
    # # Removes endings from Juliet filenames, such as .java, _bad, _goodB2G, a, b, c etc. # #
    def __strip_filename_of_endings(self, filename):
        stripped = filename
        if (stripped.endswith('.java')):
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15.java
            stripped = stripped[:-5]
        if (re.search('((_good)|(_bad))[0-9]*((B2G)|(G2B))?$', stripped)):
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15_goodB2G
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15_bad
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15_good1
            stripped = re.sub('((_good)|(_bad))([0-9])*((B2G)|(G2B))?$', '', stripped)
        if (re.search('_[0-9]+[a-z]$', stripped)):
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15a
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15d
            stripped = stripped[:-1]
        return stripped

    # # Adds a CSV formated line to the output buffer, which later can be written to a CSV file # #
    def __add_output_line(self, cwe, method, vultype, correct_place, correct_type):
        self.__output_buffer += ('"%s","%s","%s","%s","%s"\n' % (cwe, method, vultype, correct_place, correct_type))
    
    # # Checks if a detection is correct (true positive) based on the filename and the method where it was detected # #
    def __is_true_positive(self, method, filename):
        return method in ['bad', 'bad_source', 'badSink', 'badSource', 'helperBad'] or filename.endswith('_bad.java')
    
    # # Adds a correct detection (true positive) to the counter dictionary # #
    def __add_correct_detection(self, stripped_filename, cwe):
        detection_data = self.__detections_by_cwe.get(cwe, DetectionData(cwe))
        detection_data.correctly_detected_vulnerabilities[stripped_filename] = detection_data.correctly_detected_vulnerabilities.get(stripped_filename, 0) + 1
        self.__detections_by_cwe[cwe] = detection_data
        # self.__correctly_detected_vulnerabilities[stripped_filename] = self.__correctly_detected_vulnerabilities.get(stripped_filename, 0) + 1

    # # Adds a wrong detection (false positive) to the counter # #
    def __add_wrong_detection(self, stripped_filename, cwe):
        detection_data = self.__detections_by_cwe.get(cwe, DetectionData(cwe))
        detection_data.wrong_detections += 1
        detection_data.wrong_detections_per_testcase[stripped_filename] = detection_data.wrong_detections_per_testcase.get(stripped_filename, 0) + 1
        self.__detections_by_cwe[cwe] = detection_data

    # # Adds a n unrelevant detection to the counter # #
    def __add_unrelevant_detection(self, cwe):
        detection_data = self.__detections_by_cwe.get(cwe, DetectionData(cwe))
        detection_data.unrelevant_detections += 1
        self.__detections_by_cwe[cwe] = detection_data
    
    # # Prints one row of "CWE, TP, FP, FN, Recall, Prec., Disc.%, Not relevant" in a nicely formated way # #
    def __print_detection_table_row(self, cwe, tp, fp, fn, recall, precision, discrimination, unrelevant):
        if (not isinstance(recall, str)):
            recall = ('%.0f%%' % recall)
        if (not isinstance(precision, str)):
            precision = ('%.0f%%' % precision)
        if (not isinstance(discrimination, str)):
            discrimination = ('%.0f%%' % discrimination)
        print('%-7s %-7s %-7s %-7s %-7s %-7s %-7s %s' % (cwe, tp, fp, fn, recall, precision, discrimination, unrelevant))