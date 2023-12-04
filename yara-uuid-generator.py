import argparse
import os
import logging
import re
import uuid
from pprint import pprint
import plyara
from plyara.utils import generate_hash


def generate_uuid_from_hash(hash_value):
    """
    Generate a UUID from a hash
    """
    return uuid.uuid5(uuid.NAMESPACE_DNS, hash_value)


def process_files(input_path, output_path, replace_files):
    """
    Process all files in the input directory
    """
    logging.info('Processing files in directory: %s', input_path)

    # Check if the output directory exists
    if not replace_files:
        # Create the output directory
        os.mkdir(output_path)

    # Process all files in the input directory
    for filename in os.listdir(input_path):
        if os.path.isfile(os.path.join(input_path, filename)):
            # if the file has a *.yar or *.yara extension
            if filename.endswith(".yar") or filename.endswith(".yara"):
                # Process the file
                process_file(input_path, output_path, filename, replace_files)


def process_file(input_path, output_path, filename, replace_files):
    """
    Process a single file
    """
    logging.info('Processing file: %s', filename)

    # We keep the rule name, the UUID and the indentation format in a list for the replacement
    rule_name_uuid_list = []

    # Read the file
    with open(os.path.join(input_path, filename), 'r', encoding="utf-8") as f:
        yara_file_content = f.read()

    # Parse the file
    yara_parser = plyara.Plyara()
    yara_rules = yara_parser.parse_string(yara_file_content)

    # Generate a UUID for each rule
    for rule in yara_rules:
        # Print the rule
        #pprint(rule)

        # Calculate the logic hash
        logic_hash = generate_hash(rule)

        # Calculate a UUID for the rule hash
        rule_uuid = generate_uuid_from_hash(logic_hash)

        # Log the rule Rule Name and UUID
        logging.info('Rule Name: %s UUID: %s', rule['rule_name'], rule_uuid)

        # Determine the indentation of the meta section
        meta_indentation = determine_meta_indentation(rule)

        # Add the rule name, the UUID and the indentation format to the list
        rule_name_uuid_list.append((rule['rule_name'], rule_uuid, meta_indentation))

    # Now we replace the rules in place
    # First we split the content of the file into lines
    yara_rule_lines = yara_file_content.split('\n')
    yara_rule_lines_copy = yara_rule_lines.copy()
    # Now we loop over the lines and insert the UUIDs in the meta data section when we find the rule name
    check_for_meta_section = False
    new_meta_line = ""
    number_of_inserts = 0
    meta_section_found = False
    for i, line in enumerate(yara_rule_lines_copy):
        logging.debug("Line: '%s'", line)

        # Whenever we find a line that contains "strings:" or "condition:" we insert the new meta data line before that line
        if check_for_meta_section and ( "strings:" in line or "condition:" in line ):
            logging.debug("Inserting new meta data line: '%s'", new_meta_line)
            # If the rules doesn't have a meta section yet, we add it
            if not meta_section_found:
                logging.debug("Adding meta section")
                # Insert the meta section
                yara_rule_lines.insert(i + number_of_inserts, "meta:")
                # Increase the number of inserts
                number_of_inserts += 1
            # Insert the new meta data line before the current line
            yara_rule_lines.insert(i + number_of_inserts, new_meta_line)
            # Reset the new meta data line
            new_meta_line = ""
            # Reset the marker that we check for the meta data section
            check_for_meta_section = False
            # Increase the number of inserts
            number_of_inserts += 1
        # Also reset the marker when we find the next rule (a line that begins with "rule ")
        elif check_for_meta_section and line.startswith("rule "):
            logging.debug("Resetting new meta data line")
            # Reset the new meta data line
            new_meta_line = ""
            # Reset the marker that we check for the meta data section
            check_for_meta_section = False
        # Don't add a rule UUID if the rule already has a UUID
        elif check_for_meta_section and "uuid = " in line:
            logging.debug("Rule already has a UUID")
            # Reset the new meta data line
            new_meta_line = ""
            # Reset the marker that we check for the meta data section
            check_for_meta_section = False
        # Check if a meta section is present
        elif "meta:" in line:
            logging.debug("Meta section found")
            # Set a marker that we found the meta section
            meta_section_found = True

        # Loop over the rule name, UUID and indentation format list
        for rule_name_uuid in rule_name_uuid_list:
            # Check if the rule name is in the line
            if line.startswith("rule ") and rule_name_uuid[0] in line:
                # Now we create the new meta data line and prepend the indentation format
                new_meta_line = rule_name_uuid[2] + 'uuid = "' + str(rule_name_uuid[1]) + '"'
                logging.debug("New meta data line: '%s'", new_meta_line)
                # We set a marker that we now check for the meta data section
                check_for_meta_section = True
                # Reset the meta section found marker
                meta_section_found = False

    # Replace the input file with the new file
    if replace_files:
        # Write the file
        with open(os.path.join(input_path, filename), 'w', encoding="utf-8") as f:
            f.write('\n'.join(yara_rule_lines))

    # or write the new file to the output directory
    else:
        # If output path ends with *.yar, write it to a single file with the same name
        if output_path.endswith(".yar"):
            # Write the file
            with open(output_path, 'a', encoding="utf-8") as f:
                f.write('\n'.join(yara_rule_lines))
        # Otherwise write the file to the output directory
        else:
            # Check if the output directory exists and create it if necessary
            if not os.path.exists(output_path):
                os.mkdir(output_path)
            # Write the file
            with open(os.path.join(output_path, filename), 'w', encoding="utf-8") as f:
                f.write('\n'.join(yara_rule_lines))


def determine_meta_indentation(rule):
    """
    Determine the indentation of the meta section
    """
    # Set the default indentation
    indentation = '   '

    # Regex pattern
    pattern = re.compile(r'[^\s\t]')

    # Check if the rule has a meta section
    if 'raw_meta' in rule:
        # The raw_meta field value looks like this:
        # 'raw_meta': 'meta:\n'
        #     '      description = "Detects NatBypass tool (also used by '
        #
        # We try to find out what follows the "meta:\n" until the first meta data value begins

        # We split the raw_meta field value by the newline character
        raw_meta_lines = rule['raw_meta'].split('\n')

        # Check each line and start with the second line
        for meta_line in raw_meta_lines[1:]:
            # Regex match that line
            match = pattern.search(meta_line)
            # If we found a match
            if match:
                # The indentation is the part of the line before the first meta data value begins
                indentation = meta_line[0:match.start()]
                # Log the indentation
                logging.debug("Meta indentation: '%s'", indentation)
                # We are done
                break

    return indentation


if __name__ == "__main__":

    # Parse the arguments
    parser = argparse.ArgumentParser(description='Yara UUID Generator')
    parser.add_argument('-i', '--input', help='Input file or directory', required=True)
    parser.add_argument('-o', '--output', help='Output file or directory', required=False, default='output')
    parser.add_argument('-d', '--debug', help='Enable debug logging', required=False, action='store_true')
    args = parser.parse_args()

    # Initialize the logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Set the level of the plyara logger to warning
    logging.getLogger('plyara').setLevel(logging.WARNING)
    logging.getLogger('tzlocal').setLevel(logging.CRITICAL)
    # Create a handler for the command line
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if args.debug else logging.INFO)
    # Create a handler for the log file
    fh = logging.FileHandler("yara-uuid-generator.log")
    fh.setLevel(logging.DEBUG)
    # Create a formatter for the log messages that go to the log file
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Create a formatter for the log messages that go to the command line
    formatter_cmd = logging.Formatter('%(message)s')
    # Add the formatter to the handlers
    ch.setFormatter(formatter_cmd)
    fh.setFormatter(formatter)
    # Add the handlers to the logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    # Log the a startup message
    logger.info('Starting Yara UUID Generator')

    # If no output directory is specified, we replace the files in the input directory
    REPLACE_FILES = False
    if args.output == 'output':
        # Set a marker to indicate that we are overwriting the input files
        REPLACE_FILES = True

    # Check if the input file or directory exists
    if not os.path.exists(args.input):
        logger.error('Input file or directory does not exist')
        exit(1)

    # Check if the input is a file
    if os.path.isfile(args.input):
        # Process the file
        process_file(os.path.dirname(args.input), args.output, os.path.basename(args.input), REPLACE_FILES)
    # Input is a directory
    else:
        # Process all files in the input directory
        process_files(args.input, args.output, REPLACE_FILES)
