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

    'CWE78':   444,  # OS Command Injection
    'CWE89':  2220,  # SQL Injection
    'CWE90':   444,  # LDAP Injection
    'CWE113': 1332,  # HTTP Response Splitting
    'CWE643':  444,  # XPath Injection

    #                                                 #
    #  2   B R O K E N   A U T H E N T I C A T I O N  #
    #                                                 #

    'CWE259':  111,  # Use of Hard-coded Password

    #                                                 #
    #  5   B R O K E N   A C C E S S   C O N T R O L  #
    #                                                 #

    'CWE23':   444,  # Relative Path Traversal
    'CWE36':   444,  # Absolute Path Traversal

    #                                                           #
    #  7   C R O S S - S I T E   S C R I P T I N G   ( X S S )  #
    #                                                           #

    'CWE80':   666,  # Basic XSS
    'CWE81':   333,  # Improper Neutralization of Script in an Error Message
    'CWE83':   333  # Improper Neutralization of Script in Attributes in a Web Page
}

# Dictionary that includes number of sinks per test case by CWE entry for Juliet Test Suite v1.2 and v1.3.
num_sinks = {

    #                         #
    #  1   I N J E C T I O N  #
    #                         #

    'CWE78':     1,  # OS Command Injection
    'CWE89':     5,  # SQL Injection
    'CWE90':     1,  # LDAP Injection
    'CWE113':    3,  # HTTP Response Splitting
    'CWE643':    1,  # XPath Injection

    #                                                 #
    #  2   B R O K E N   A U T H E N T I C A T I O N  #
    #                                                 #

    'CWE259':    1,  # Use of Hard-coded Password

    #                                                 #
    #  5   B R O K E N   A C C E S S   C O N T R O L  #
    #                                                 #

    'CWE23':     1,  # Relative Path Traversal
    'CWE36':     1,  # Absolute Path Traversal

    #                                                           #
    #  7   C R O S S - S I T E   S C R I P T I N G   ( X S S )  #
    #                                                           #

    'CWE80':     1,  # Basic XSS
    'CWE81':     1,  # Improper Neutralization of Script in an Error Message
    'CWE83':     1  # Improper Neutralization of Script in Attributes in a Web Page

}

# Dictionary that includes number of functional variants per test case by CWE entry for Juliet Test Suite v1.2 and v1.3.
num_func_vars = {

    #                         #
    #  1   I N J E C T I O N  #
    #                         #

    'CWE78':    12,  # OS Command Injection
    'CWE89':    12,  # SQL Injection
    'CWE90':    12,  # LDAP Injection
    'CWE113':   12,  # HTTP Response Splitting
    'CWE643':   12,  # XPath Injection

    #                                                 #
    #  2   B R O K E N   A U T H E N T I C A T I O N  #
    #                                                 #

    'CWE259':    3,  # Use of Hard-coded Password

    #                                                 #
    #  5   B R O K E N   A C C E S S   C O N T R O L  #
    #                                                 #

    'CWE23':    12,  # Relative Path Traversal
    'CWE36':    12,  # Absolute Path Traversal

    #                                                           #
    #  7   C R O S S - S I T E   S C R I P T I N G   ( X S S )  #
    #                                                           #

    'CWE80':    18,  # Basic XSS
    'CWE81':     9,  # Improper Neutralization of Script in an Error Message
    'CWE83':     9  # Improper Neutralization of Script in Attributes in a Web Page

}

# The flow variant (as numbers) corresponding to the filename numbers in the Juliet Test Suite.
flow_var_baseline_nums = [1]
flow_var_control_flow_nums = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 21, 22]
flow_var_data_flow_nums = [31, 41, 42, 45, 51, 52, 53, 54, 61, 66, 67, 68, 71, 72, 73, 74, 75, 81]
flow_var_all_nums = flow_var_baseline_nums + flow_var_control_flow_nums + flow_var_data_flow_nums

# Contains all the names of the functional variants. Used to remove the sink name from the filename later in the code.
functional_vars_all = ['Environment','connect_tcp','console_readLine','database','File','getCookies','getParameter','PropertiesFile','getQueryString','listen_tcp','Property','URLConnection',
                       'driverManager', 'kerberosKey', 'passwordAuth',
                       'Servlet_Environment','Servlet_connect_tcp','Servlet_console_readLine','Servlet_database','Servlet_File','Servlet_getCookies','Servlet_getParameter','Servlet_PropertiesFile','Servlet_getQueryString','Servlet_listen_tcp','Servlet_Property','Servlet_URLConnection',
                       'CWE182_Servlet_Environment','CWE182_Servlet_connect_tcp','CWE182_Servlet_console_readLine','CWE182_Servlet_database','CWE182_Servlet_File','CWE182_Servlet_getCookies','CWE182_Servlet_getParameter','CWE182_Servlet_PropertiesFile','CWE182_Servlet_getQueryString','CWE182_Servlet_listen_tcp','CWE182_Servlet_Property','CWE182_Servlet_URLConnection']

class DetectionData:
    def __init__(self, cwe):
        self.cwe = cwe

        # __detections_by_func_var contains:
        # functional variant #1:
        #   flow_var: [TP, FP]
        #   flow_var: [TP, FP]
        # functional variant #2:
        #   flow_var: [TP, FP]
        # ...
        self.detections_by_func_var = {}

        self.detections_total = dict((key, [0, 0]) for key in flow_var_all_nums)
        self.unrelevant_detections = 0

    # # Add a detection for a specific CWE, can be true positive, false positive, related, unrelated # #
    def add_detection(self, func_var, flow_var, is_correct_place, is_correct_vulntype):
        flow_var = int(flow_var)
        func_var_data = self.detections_by_func_var.get(
            func_var, dict((key, [0, 0]) for key in flow_var_all_nums))

        if (is_correct_place and is_correct_vulntype):
            if (func_var_data[flow_var][0] + 1) > num_sinks[self.cwe]:
                print('Warning!', 'Ignoring a TP for', func_var, flow_var, '. Parser only allows max 1 TP per file')
            else:
                func_var_data[flow_var][0] += 1
                self.detections_total[flow_var][0] += 1
        elif (not is_correct_place and is_correct_vulntype):
            func_var_data[flow_var][1] += 1
            self.detections_total[flow_var][1] += 1
        else:
            self.unrelevant_detections += 1

        self.detections_by_func_var[func_var] = func_var_data

    # # Optional method to combine functional variants with the same results # #
    def combine_equal_func_vars(self):
        for func_var_outer, flow_var_detection_data_outer in self.detections_by_func_var.items():
            for func_var_inner, flow_var_detection_data_inner in self.detections_by_func_var.items():
                if func_var_outer == func_var_inner:
                    # Skipping, comparing the same functional variant
                    continue
                elif flow_var_detection_data_outer == flow_var_detection_data_inner:
                    # inner and outer are the same. Combining them
                    new_key_name = func_var_outer + ', ' + func_var_inner
                    self.detections_by_func_var[new_key_name] = flow_var_detection_data_outer
                    del self.detections_by_func_var[func_var_outer]
                    del self.detections_by_func_var[func_var_inner]
                    # Restarting combination due to changes in dict
                    self.combine_equal_func_vars()
                    return
    
    # # Optional method to alphabetically sort functional variants that have been combined using combine_equal_func_vars() method # #
    def sort_combined_func_vars(self):
        for func_var, flow_var_detection_data in self.detections_by_func_var.items():
            name_split = func_var.split(', ')
            sorted_name_split = sorted(name_split)
            if name_split != sorted_name_split:
                # Not sorted. Sorting them
                new_key_name = ', '.join(sorted_name_split)
                self.detections_by_func_var[new_key_name] = flow_var_detection_data
                del self.detections_by_func_var[func_var]
                # Restarting sorting due to changes in dict
                self.sort_combined_func_vars()
                return


class PluginCommon:
    # Used to write CVE file
    __output_buffer = ''

    # Contains the results for each CWE. Key: string CWE, Value: DetectionData instance
    __detections_by_cwe = {}

    # # Add a detection, can be true positive, false positive, related, unrelated # #
    def add_detection(self, filename, cwe, method, vultype, correct_vultype):
        correct_place = self.__is_true_positive(method, filename)
        self.__add_output_line(filename, method, vultype, correct_place, correct_vultype)
        detection_data = self.__detections_by_cwe.get(cwe, DetectionData(cwe))
        detection_data.add_detection(self.get_func_var_without_sink(filename), self.get_flow_var_from_filename(filename), correct_place, correct_vultype)
        self.__detections_by_cwe[cwe] = detection_data

    # # Calculates TP, FP, FN, recall, prec, and disc rate for each functional variant in the provided DetectionData instance, then prints it # #
    def calculate_and_print_metrics(self, detection_data):
        if (not isinstance(detection_data, DetectionData)):
            print('ERROR!', 'detection_data must be of type DetectionData')
            raise Exception('detection_data must be of type DetectionData')
        for func_var, flow_var_detection_data in detection_data.detections_by_func_var.items():
            print('#######', func_var)
            self.print_flow_variant_results('Type', 'TP', 'FP', 'FN', 'rec', 'prec', 'disc')
            
            # Baseline for functional variant
            self.calculate_and_print_metrics_for_flow_type(detection_data, flow_var_detection_data, flow_var_baseline_nums, 'BL')
            # Control-flow for functional variant
            self.calculate_and_print_metrics_for_flow_type(detection_data, flow_var_detection_data, flow_var_control_flow_nums, 'CF')
            # Data-flow for functional variant
            self.calculate_and_print_metrics_for_flow_type(detection_data, flow_var_detection_data, flow_var_data_flow_nums, 'DF')
            # Total for functional variant
            self.calculate_and_print_metrics_for_flow_type(detection_data, flow_var_detection_data, flow_var_all_nums, 'Total')
        
        print('#######', 'Total', '#######')
        self.print_flow_variant_results('Type', 'TP', 'FP', 'FN', 'rec', 'prec', 'disc')
        self.calculate_and_print_metrics_for_flow_type(detection_data, detection_data.detections_total, flow_var_baseline_nums, 'BL', num_func_vars[detection_data.cwe])
        self.calculate_and_print_metrics_for_flow_type(detection_data, detection_data.detections_total, flow_var_control_flow_nums, 'CF', num_func_vars[detection_data.cwe])
        self.calculate_and_print_metrics_for_flow_type(detection_data, detection_data.detections_total, flow_var_data_flow_nums, 'DF', num_func_vars[detection_data.cwe])
        self.calculate_and_print_metrics_for_flow_type(detection_data, detection_data.detections_total, flow_var_all_nums, 'Total', num_func_vars[detection_data.cwe])

        print('#######', 'Other info', '#######')
        print('Not relevant:', detection_data.unrelevant_detections)
        print('Total numb. of vuln. in Juliet CWE:', num_cases[detection_data.cwe])
        print('Total numb. of func. var. in Juliet CWE:', num_func_vars[detection_data.cwe])
        print('Total numb. of sinks per func. var. in Juliet CWE:', num_sinks[detection_data.cwe])

    # # Calculates TP, FP, FN, recall, prec, and disc rate for the specific flow variant specified, then prints it # #
    def calculate_and_print_metrics_for_flow_type(self, detection_data, flow_type_detection_data, flow_type_numbers, flow_type_text, total_multiplier=1):
        tp, fp, fn, recall, prec, disc = self.calculate_metrics_for_flow_var(detection_data.cwe, flow_type_detection_data, flow_type_numbers, total_multiplier)
        self.print_flow_variant_results(flow_type_text, tp, fp, fn, recall, prec, disc)
    
    # # Calculates TP, FP, FN, recall, prec, and disc rate for the specific flow variant specified # #
    # # total_multiplier is used when calculating the total for all functional variants. total_multiplier should then be set to the number of functional variants in the CWE. # #
    def calculate_metrics_for_flow_var(self, cwe, flow_var_results, flow_var_nums, total_multiplier=1):
        tp = 0
        fp = 0
        for flow_var_case in flow_var_nums:
            tp += flow_var_results[flow_var_case][0]
            fp += flow_var_results[flow_var_case][1]
        fn = (len(flow_var_nums)*num_sinks[cwe]*total_multiplier) - tp
        recall = 100*tp/(len(flow_var_nums)*num_sinks[cwe]*total_multiplier)
        precision = 100*tp/max(1, tp+fp)
        disc_rate = 100*max(0, (tp-fp))/(len(flow_var_nums)*num_sinks[cwe]*total_multiplier)

        return tp, fp, fn, recall, precision, disc_rate

    # # Outputs a table of detection data to the console # #
    def print_flow_variant_results(self, flow_var_type, tp, fp, fn, recall, precision, disc_rate):
        if (not isinstance(recall, str)):
            recall = ('%.0f%%' % recall)
        if (not isinstance(precision, str)):
            precision = ('%.0f%%' % precision)
        if (not isinstance(disc_rate, str)):
            disc_rate = ('%.0f%%' % disc_rate)
        print('%-7s %-7s %-7s %-7s %-7s %-7s %s' %
                (flow_var_type, tp, fp, fn, recall, precision, disc_rate))

    # # Outputs the CSV file # #
    def write_output(self, filename):
        with open(filename, 'w') as f:
            f.writelines(self.__output_buffer)
        print('Detailed output written to %s' % filename)

    # # Adds a CSV formated line to the output buffer, which later can be written to a CSV file # #
    def __add_output_line(self, cwe, method, vultype, correct_place, correct_type):
        self.__output_buffer += ('"%s","%s","%s","%s","%s"\n' % (cwe, method, vultype, correct_place, correct_type))

    # # Outputs the results to the console # #
    def print_detections(self):
        for cwe, detection_data in self.__detections_by_cwe.items():
            print('')
            print('####################')
            print(cwe)
            print('--------------------')
            detection_data.combine_equal_func_vars()
            detection_data.sort_combined_func_vars()
            self.calculate_and_print_metrics(detection_data)

    # # Gets CWE code from Juliet filename # #
    def get_cwe_from_filename(self, filename):
        return filename.split('_')[0]

    # # Gets the functional variant (and possibly the sink) from the filename. Removes CWE, file endings, and flow variant # #
    def get_func_var_with_sink_from_filename(self, filename):
        no_endings = self.__strip_filename_of_endings(filename)
        func_var_and_flow = no_endings.split('__')[1]
        func_var = '_'.join(func_var_and_flow.split('_')[:-1])
        return func_var

    # # Gets the functional variant (but never the sink) from the filename. Removes CWE, file endings, possible sink, and flow variant # #
    def get_func_var_without_sink(self, filename):
        func_var_with_sink = self.get_func_var_with_sink_from_filename(filename)
        for func_var_name in functional_vars_all:
            if func_var_with_sink.startswith(func_var_name):
                return func_var_name
        print('ERROR!', 'Failed to find the functional variant', '|', filename, '|', func_var_with_sink)
        raise Exception('Failed to find the functional variant')

    # # Gets the flow variant (as a string) from the filename # #
    def get_flow_var_from_filename(self, filename):
        no_endings = self.__strip_filename_of_endings(filename)
        flow_var = no_endings.split('_')[-1]
        return flow_var

    # # Checks if a detection is correct (true positive) based on the filename and the method where it was detected # #
    def __is_true_positive(self, method, filename):
        return method in ['bad', 'bad_source', 'badSink', 'badSource', 'helperBad'] or filename.endswith('_bad.java')

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
            stripped = re.sub(
                '((_good)|(_bad))([0-9])*((B2G)|(G2B))?$', '', stripped)
        if (re.search('_[0-9]+[a-z]$', stripped)):
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15a
            # e.g. CWE78_OS_Command_Injection__PropertiesFile_15d
            stripped = stripped[:-1]
        return stripped
