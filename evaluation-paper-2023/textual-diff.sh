#!/usr/bin/env python

import sys, json

def main(baseline_json: str, alternative_json: str):
  print("Usage: python3 ./textual-diff.sh <path-to-gcov-baseline.json> <path-to-gcov-new.json>")
  baseline = load_covered_lines(baseline_json)
  alternative = load_covered_lines(alternative_json)
  found_any_differences = 0

  # compare covered lines for each source file
  for filename in sorted(baseline):
    # print(filename)  
    difference = baseline[filename] - alternative[filename]

    if not difference:
      # print(f"info: {filename}: ok")
      continue

    for lineno in sorted(difference):
      found_any_differences = found_any_differences + 1
      print(f"[LINE] error: {filename}: {lineno}: not covered in {alternative_json}")

  baseline_f = load_covered_functions(baseline_json)
  alternative_f = load_covered_functions(alternative_json)
  found_any_differences_f = 0
  print("=======================\n\n FUNCTIONS\n=======================\n")

  # compare covered lines for each source file
  for filename in sorted(baseline_f):
    # print(filename)  
    difference_f = baseline_f[filename] - alternative_f[filename]

    if not difference_f:
      # print(f"info: {filename}: ok")
      continue

    for function in sorted(difference_f):
      found_any_differences_f = found_any_differences_f + 1
      print(f"[FUN] error: {filename}: {function}: not covered in {alternative_json}")
      

  print("Number of additional covered lines: "+ str(found_any_differences))
  print("Number of additional called functions: "+ str(found_any_differences_f))

  if found_any_differences:
    sys.exit(1)


def load_covered_lines(gcovr_json_file: str):
  # JSON format is documented at
  # <https://gcovr.com/en/stable/output/json.html#json-format-reference>

  with open(gcovr_json_file) as f:
    data = json.load(f)

  # The JSON format may change between versions


  covered_lines = dict()
  for filecov in data["files"]:
    covered_lines[filecov["file"]] = set(
      linecov["line_number"]
      for linecov in filecov["lines"]
      if linecov["count"] != 0
    )

  return covered_lines

def load_covered_functions(gcovr_json_file: str):
  # JSON format is documented at
  # <https://gcovr.com/en/stable/output/json.html#json-format-reference>

  with open(gcovr_json_file) as f:
    data = json.load(f)

  # The JSON format may change between versions


  covered_functions = dict()
  for filecov in data["files"]:
    covered_functions[filecov["file"]] = set(
      covered_function["name"]
      for covered_function in filecov["functions"]
      if covered_function["execution_count"] != 0
    )
# "functions": [{"execution_count": 0, "lineno": 151, "name": "OPENSSL_DIR_end"},
  return covered_functions


if __name__ == "__main__":
  main(*sys.argv[1:])
