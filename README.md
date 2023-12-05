# YARA UUID Generator

This is a simple tool to generate YARA UUIDs and add them to the meta data section of each rule.

## Features

- Generate UUIDs for all rules in a directory
- The UUID is based on the "generate_hash" function of the plyara library (it's not random; it will always generate the same UUID for the same rule unless its strings or condition changes)
- Replaces the rules in place without altering their formatting
- Takes care of the indentation used in the meta data section
- Checks if a UUID already exists and skips the rule if so

## Usage

```bash
$ python3 yara_uuid_generator.py -h
usage: yara_uuid_generator.py [-h] [-r RULES] [-o OUTPUT]
```

## Example

```bash
$ python3 yara_uuid_generator.py -r ./examples -o ./examples-output
```

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
      id = "54af4d84-72f7-5ec4-b0bf-7ba228fdf508"
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