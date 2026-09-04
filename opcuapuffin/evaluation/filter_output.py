#!/usr/bin/env python3

from datetime import datetime
import sys

def filter_stdout():
   with open("measurements.txt", "w", encoding="utf-8") as file:
      current_size = 0
      last_line = ""
      try:
        # Read standard input line by line
        for line in sys.stdin:
            if "(GLOBAL) clients" in line:
                start = line.index("corpus:") + 7
                stop  = line[start: -1].index(",") + start
                size  = int(line[start:stop])
                last_line = line
                if size > current_size + current_size / 100:
                     current_size = size
                     # Displays the corresponding line without adding a duplicate line break
                     sys.stdout.write(line)
                     # Forces the buffer to be flushed for instant display
                     sys.stdout.flush()
                     # Writing in parallel to the file that will be used for post-processing
                     file.write(line[0:19] + ', ' + str(size) +"\n")
                     file.flush()
      except KeyboardInterrupt:
         # To exit cleanly with Ctrl+C
         line = last_line
         start = line.index("corpus:") + 7
         stop  = line[start: -1].index(",") + start
         size  = int(line[start:stop])
         if size > current_size:
             sys.stdout.write(line)
             sys.stdout.flush()
             file.write(line[0:19] + ', ' + str(size) +"\n")
             file.flush()
         sys.exit(0)

if __name__ == "__main__":
      filter_stdout()
