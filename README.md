# YARA UUID Generator

`yara-uuid-generator.py` adds a deterministic `id` value to the `meta` section of YARA rules.

The UUID is derived from [`plyara.utils.generate_hash`](https://github.com/plyara/plyara), but only at the moment the `id` is first assigned. After that, the `id` is preserved and is not recalculated automatically when the rule changes later.

This is the key distinction from using the `plyara` rule hash directly:

- `plyara` hash: fingerprint of the rule's current logic
- This tool's UUID: stable rule identity assigned once

That allows you to run the tool on a rule set once, assign deterministic UUIDs, and keep those UUIDs for the rest of each rule's lifetime.

If two identical rules exist in two different rule sets at the time of assignment, they receive the same UUID. If those rules diverge later, they still keep the UUID they were originally assigned.

## What It Does

- Adds `id = "<uuid>"` to rules that do not already define one
- Uses the current `plyara` rule hash only to derive the initial UUID
- Leaves existing `id` values untouched, even if the rule logic changes later
- Preserves existing `meta` indentation
- Creates a `meta` section when a rule does not have one yet
- Supports regular, `private`, and `global` rule declarations
- Processes a single file or every `.yar` and `.yara` file in a directory
- Writes output in place, to another directory, or to a combined output file

## Requirements

- Python 3
- `plyara`

## Installation

```bash
python3 -m venv .venv
./.venv/bin/pip install plyara
```

## Usage

```bash
python3 yara-uuid-generator.py -i INPUT [-o OUTPUT] [-d]
```

### Arguments

- `-i`, `--input`: Input YARA file or directory
- `-o`, `--output`: Output file or directory. If omitted, the input file(s) are updated in place.
- `-d`, `--debug`: Enable debug logging

## Output Modes

### Update files in place

```bash
python3 yara-uuid-generator.py -i ./examples
```

### Write processed files to another directory

```bash
python3 yara-uuid-generator.py -i ./examples -o ./examples-output
```

### Combine a directory of rules into one output file

```bash
python3 yara-uuid-generator.py -i ./examples -o ./combined.yar
```

### Process one file into another file

```bash
python3 yara-uuid-generator.py -i ./examples/example.yar -o ./example-with-ids.yar
```

## Example

### Before

```yara
rule HKTL_NATBypass_Dec22_1 : T1090 {
   meta:
      description = "Detects NatBypass tool (also used by APT41)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cw1997/NATBypass"
      date = "2022-12-27"
      score = 80
      hash1 = "4550635143c9997d5499d1d4a4c860126ee9299311fed0f85df9bb304dca81ff"
   strings:
      $x1 = "nb -slave 127.0.0.1:3389 8.8.8.8:1997" ascii
      $x2 = "| Welcome to use NATBypass Ver" ascii

      $s1 = "main.port2host.func1" ascii fullword
      $s2 = "start to transmit address:" ascii
      $s3 = "^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])"
   condition:
      filesize < 8000KB
      and (
         1 of ($x*)
         or 2 of them
      ) or 3 of them
}
```

### After

```yara
rule HKTL_NATBypass_Dec22_1 : T1090 {
   meta:
      description = "Detects NatBypass tool (also used by APT41)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cw1997/NATBypass"
      date = "2022-12-27"
      score = 80
      hash1 = "4550635143c9997d5499d1d4a4c860126ee9299311fed0f85df9bb304dca81ff"
      id = "365d17d4-8686-5614-90ec-55738c1246d4"
   strings:
      $x1 = "nb -slave 127.0.0.1:3389 8.8.8.8:1997" ascii
      $x2 = "| Welcome to use NATBypass Ver" ascii

      $s1 = "main.port2host.func1" ascii fullword
      $s2 = "start to transmit address:" ascii
      $s3 = "^(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])\\.(\\d{1,2}|1\\d\\d|2[0-4]\\d|25[0-5])"
   condition:
      filesize < 8000KB
      and (
         1 of ($x*)
         or 2 of them
      ) or 3 of them
}
```

## Notes

- Rules that already contain `meta.id` are left unchanged.
- The UUID is intended to act as a stable identifier, not as a live hash of the current rule content.
- A log file named `yara-uuid-generator.log` is written to the current working directory.
