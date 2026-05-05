import argparse
import logging
import os
import re
import uuid

import plyara
from plyara.utils import generate_hash

RULE_FILE_EXTENSIONS = (".yar", ".yara")
SECTION_HEADERS = {"meta:", "strings:", "condition:"}
NON_WHITESPACE_PATTERN = re.compile(r"[^\s\t]")


def generate_uuid_from_hash(hash_value):
    """
    Generate a deterministic UUID from a rule hash.
    """
    return uuid.uuid5(uuid.NAMESPACE_DNS, hash_value)


def is_rule_file(path):
    """
    Check whether the provided path targets a YARA file.
    """
    return path.lower().endswith(RULE_FILE_EXTENSIONS)


def ensure_parent_directory(path):
    """
    Create the parent directory for a file path if needed.
    """
    parent_directory = os.path.dirname(path)
    if parent_directory:
        os.makedirs(parent_directory, exist_ok=True)


def get_rule_files(input_path):
    """
    Return the YARA files in a directory in deterministic order.
    """
    return sorted(
        filename
        for filename in os.listdir(input_path)
        if os.path.isfile(os.path.join(input_path, filename)) and is_rule_file(filename)
    )


def line_indentation(line):
    """
    Return the leading indentation of a line.
    """
    return line[:len(line) - len(line.lstrip())]


def rule_has_uuid(rule):
    """
    Check whether a rule already contains an id metadata entry.
    """
    return any("id" in metadata_entry for metadata_entry in rule.get("metadata", []))


def find_rule_section(lines, start_index, stop_index, section_name):
    """
    Find the first occurrence of a rule section header.
    """
    for index in range(start_index, stop_index):
        if lines[index].strip() == section_name:
            return index

    return None


def find_insertion_section(lines, start_index, stop_index):
    """
    Find the section before which a new meta entry should be inserted.
    """
    for index in range(start_index, stop_index):
        if lines[index].strip() in {"strings:", "condition:"}:
            return index

    return None


def determine_meta_indentation(rule):
    """
    Determine the indentation used for entries inside the meta section.
    """
    indentation = "   "

    if "raw_meta" not in rule:
        return indentation

    raw_meta_lines = rule["raw_meta"].split("\n")
    for meta_line in raw_meta_lines[1:]:
        match = NON_WHITESPACE_PATTERN.search(meta_line)
        if match:
            indentation = meta_line[:match.start()]
            logging.debug("Meta indentation: '%s'", indentation)
            break

    return indentation


def determine_new_meta_indentation(lines, start_index, stop_index):
    """
    Determine indentation for a newly created meta section and its entries.
    """
    section_index = find_insertion_section(lines, start_index, stop_index)
    if section_index is None:
        raise ValueError("Could not determine where to insert a meta section")

    section_indentation = line_indentation(lines[section_index])

    for index in range(section_index + 1, stop_index):
        stripped_line = lines[index].strip()
        if not stripped_line:
            continue
        if stripped_line in SECTION_HEADERS or stripped_line == "}":
            break

        entry_indentation = line_indentation(lines[index])
        if len(entry_indentation) > len(section_indentation):
            return section_indentation, entry_indentation

    indentation_unit = "\t" if "\t" in section_indentation else "    "
    return section_indentation, section_indentation + indentation_unit


def insert_rule_uuid(lines, rule, rule_uuid):
    """
    Insert the generated UUID into a rule's meta section.
    """
    start_index = rule["start_line"] - 1
    stop_index = min(rule["stop_line"], len(lines))
    meta_section_index = find_rule_section(lines, start_index, stop_index, "meta:")
    meta_line = f'{determine_meta_indentation(rule)}id = "{rule_uuid}"'

    if meta_section_index is not None:
        insert_index = find_insertion_section(lines, meta_section_index + 1, stop_index)
        if insert_index is None:
            raise ValueError(
                f'Could not determine where to insert the UUID for rule {rule["rule_name"]}'
            )
        lines.insert(insert_index, meta_line)
        return

    insert_index = find_insertion_section(lines, start_index, stop_index)
    if insert_index is None:
        raise ValueError(f'Could not determine where to add a meta section for rule {rule["rule_name"]}')

    section_indentation, entry_indentation = determine_new_meta_indentation(
        lines,
        start_index,
        stop_index,
    )
    lines.insert(insert_index, f"{section_indentation}meta:")
    lines.insert(insert_index + 1, f'{entry_indentation}id = "{rule_uuid}"')


def transform_yara_content(yara_file_content):
    """
    Add deterministic UUIDs to rules that do not already have one.
    """
    parser = plyara.Plyara()
    yara_rules = parser.parse_string(yara_file_content)
    yara_rule_lines = yara_file_content.splitlines()
    had_trailing_newline = yara_file_content.endswith("\n")

    for rule in reversed(yara_rules):
        if rule_has_uuid(rule):
            logging.info("Rule Name: %s already has an ID; skipping", rule["rule_name"])
            continue

        logic_hash = generate_hash(rule)
        rule_uuid = generate_uuid_from_hash(logic_hash)
        logging.info("Rule Name: %s UUID: %s", rule["rule_name"], rule_uuid)
        insert_rule_uuid(yara_rule_lines, rule, rule_uuid)

    transformed_content = "\n".join(yara_rule_lines)
    if had_trailing_newline:
        transformed_content += "\n"

    return transformed_content


def transform_file(input_path, filename):
    """
    Read, transform, and return the contents of a single file.
    """
    logging.info("Processing file: %s", filename)

    with open(os.path.join(input_path, filename), "r", encoding="utf-8") as file_handle:
        yara_file_content = file_handle.read()

    return transform_yara_content(yara_file_content)


def write_file(output_path, content):
    """
    Write content to disk, creating parent directories when required.
    """
    ensure_parent_directory(output_path)

    with open(output_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(content)


def process_files(input_path, output_path, replace_files):
    """
    Process all YARA files in a directory.
    """
    logging.info("Processing files in directory: %s", input_path)
    filenames = get_rule_files(input_path)

    if not filenames:
        logging.warning("No YARA files found in directory: %s", input_path)
        return

    if replace_files:
        for filename in filenames:
            write_file(
                os.path.join(input_path, filename),
                transform_file(input_path, filename),
            )
        return

    if is_rule_file(output_path):
        combined_content = "\n\n".join(
            transform_file(input_path, filename).rstrip("\n") for filename in filenames
        )
        if combined_content:
            combined_content += "\n"
        write_file(output_path, combined_content)
        return

    os.makedirs(output_path, exist_ok=True)
    for filename in filenames:
        write_file(
            os.path.join(output_path, filename),
            transform_file(input_path, filename),
        )


def process_single_file(input_path, output_path, replace_files):
    """
    Process a single file input.
    """
    source_directory = os.path.dirname(input_path) or "."
    filename = os.path.basename(input_path)
    transformed_content = transform_file(source_directory, filename)

    if replace_files:
        write_file(input_path, transformed_content)
        return

    if is_rule_file(output_path):
        write_file(output_path, transformed_content)
        return

    os.makedirs(output_path, exist_ok=True)
    write_file(os.path.join(output_path, filename), transformed_content)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="YARA UUID Generator")
    parser.add_argument("-i", "--input", help="Input file or directory", required=True)
    parser.add_argument(
        "-o",
        "--output",
        help="Output file or directory. Omit this flag to replace files in place.",
        required=False,
        default=None,
    )
    parser.add_argument("-d", "--debug", help="Enable debug logging", required=False, action="store_true")
    args = parser.parse_args()

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    logging.getLogger("plyara").setLevel(logging.WARNING)
    logging.getLogger("tzlocal").setLevel(logging.CRITICAL)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if args.debug else logging.INFO)

    file_handler = logging.FileHandler("yara-uuid-generator.log")
    file_handler.setLevel(logging.DEBUG)

    log_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_formatter = logging.Formatter("%(message)s")

    console_handler.setFormatter(console_formatter)
    file_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.info("Starting YARA UUID Generator")

    replace_files = args.output is None

    if not os.path.exists(args.input):
        logger.error("Input file or directory does not exist")
        raise SystemExit(1)

    if os.path.isfile(args.input):
        process_single_file(args.input, args.output, replace_files)
    else:
        process_files(args.input, args.output, replace_files)
