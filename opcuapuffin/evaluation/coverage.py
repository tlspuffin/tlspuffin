#!/usr/bin/env python3

# Compute coverage.
# usage:
#   $ python3 coverage.py experiment_dir

from argparse import ArgumentParser
import csv
import glob
import json
import os
from pathlib import Path
import subprocess

# Configuration ---------------------------------------------------------------
VENDOR = "open62541"
BASE_DIR = Path(".opcuapuffin/evaluation/coverage-results-"+VENDOR)
BINARY = "./target/debug/opcuapuffin"
SEEDS_DIR = "./seeds_opcua" # OPC UA seeds are in-code, we'll use an empty dir for baseline
BATCH_SIZE = 100 
GCOVR_EXCLUDES = [
    ".*tests.*",
    ".*examples.*",
    ".*doc.*",
    ".*deps.*",
    ".*tools.*"
]

def run_cmd(cmd, check=True, capture_output=True):
    res = subprocess.run(cmd, shell=True, capture_output=capture_output, text=True)
    if check and res.returncode != 0:
        print(f"Error running: {cmd}")
        print(res.stderr)
        res.check_returncode()
    return res

def get_gcov_data():
    exclude_args = " ".join([f'-e "{x}"' for x in GCOVR_EXCLUDES])
    cmd = f'gcovr --gcov-executable "llvm-cov gcov" {exclude_args} --json-summary-pretty'
    res = run_cmd(cmd, check=False)
    return json.loads(res.stdout)

#------------------------------------------------------------------------------
def main(): # Main program
#------------------------------------------------------------------------------
   # Parse arguments:
   parser = ArgumentParser(
      prog = 'coverage.py',
      description = 'replay the given corpus with an instrumented PUT and extract coverage information'
   )
   parser.add_argument('corpus', help='directory containing the traces to replay')
   args = parser.parse_args()

   DIR = os.getcwd()
   CORPUS_DIR = args.corpus + "/corpus"
   BASE_DIR.mkdir(parents=True, exist_ok=True)
   html_dir = BASE_DIR / "html"
   html_dir.mkdir(exist_ok=True)
   cov_file = BASE_DIR / f"coverage-{VENDOR}.csv"

   # Ensure seeds dir exists (even if empty)
   Path(SEEDS_DIR).mkdir(exist_ok=True)

   # Clean up old data
   print("Cleaning up old .gcda files...")
   run_cmd("find . -name '*.gcda' -delete")

   # Get sorted corpus traces by modification time
   print(f"Scanning corpus: {CORPUS_DIR}")
   traces = sorted(glob.glob(os.path.join(CORPUS_DIR, "*.trace")), key=os.path.getmtime)
   print(f"Found {len(traces)} traces.")

   if not traces:
      print("No traces found in corpus directory!")
      return

   with open(cov_file, 'w', newline='') as csvfile:
      fieldnames = ['time', 'b_abs', 'b_per', 'b_total', 'fn_abs', 'fn_per', 'fn_total', 'l_abs', 'l_per', 'l_total']
      writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
      writer.writeheader()

      # 1. Baseline (using empty seeds dir or just initial state)
      print("Executing baseline (seeds)...")
      # opcuapuffin might not have physical seed files, but let's run it anyway
      run_cmd(f"{BINARY} --put {VENDOR} execute --index 0 -n 1000 {SEEDS_DIR}")
      data = get_gcov_data()
      writer.writerow({
         'time': "",
         'b_abs': data['branch_covered'], 'b_per': data['branch_percent'], 'b_total': data['branch_total'],
         'fn_abs': data['function_covered'], 'fn_per': data['function_percent'], 'fn_total': data['function_total'],
         'l_abs': data['line_covered'], 'l_per': data['line_percent'], 'l_total': data['line_total']
      })

      # 2. Process corpus in batches
      for i in range(0, len(traces), BATCH_SIZE):
         batch = traces[i:i + BATCH_SIZE]
         last_trace_in_batch = batch[-1]
         batch_timestamp = int(os.path.getmtime(last_trace_in_batch) * 1000)
         
         print(f"Executing batch {i // BATCH_SIZE + 1} (indices {i} to {i + len(batch) - 1})...")
         run_cmd(f"{BINARY} --put {VENDOR} execute --index {i} -n {len(batch)} {CORPUS_DIR}", check=False)
         
         print(f"Collecting coverage at timestamp {batch_timestamp}...")
         data = get_gcov_data()
         writer.writerow({
               'time': batch_timestamp,
               'b_abs': data['branch_covered'], 'b_per': data['branch_percent'], 'b_total': data['branch_total'],
               'fn_abs': data['function_covered'], 'fn_per': data['function_percent'], 'fn_total': data['function_total'],
               'l_abs': data['line_covered'], 'l_per': data['line_percent'], 'l_total': data['line_total']
         })
         csvfile.flush()

   # 3. Final Reports
   print("Generating final reports...")
   exclude_args = " ".join([f'-e "{x}"' for x in GCOVR_EXCLUDES])
   
   print("  -> Generating HTML report...")
   run_cmd(f'gcovr --gcov-executable "llvm-cov gcov" {exclude_args} --html-details --html-self-contained -o {html_dir}/index.html')
   
   print("  -> Generating Cobertura report...")
   run_cmd(f'gcovr --gcov-executable "llvm-cov gcov" {exclude_args} --cobertura {BASE_DIR}/coverage.cobertura')
   
   print("  -> Generating JSON report...")
   run_cmd(f'gcovr --gcov-executable "llvm-cov gcov" {exclude_args} --json {BASE_DIR}/coverage.json')

   print(f"\nDone. Results in {BASE_DIR}")
   #generate_dashboard(BASE_DIR, cov_file.name, VENDOR)


#------------------------------------------------------------------------------
if __name__ == "__main__":
    main()