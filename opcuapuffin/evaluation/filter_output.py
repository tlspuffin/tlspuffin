#!/usr/bin/env python3

from datetime import datetime
#import numpy as np
import sys

def filter_stdout():
   with open("measurements.txt", "w", encoding="utf-8") as file:
      file.write("measurements = [\n")
      current_size = 0
      try:
        # Lit l'entrée standard ligne par ligne en temps réel
        for line in sys.stdin:
            if "[Stats] (GLOBAL) clients" in line:
                start = line.index("corpus:") + 7
                stop  = line[start: -1].index(",") + start
                size  = int(line[start:stop]) 
                if size > current_size + current_size / 10:
                     current_size = size
                     # Affiche la ligne correspondante sans ajouter de saut de ligne doublon
                     sys.stdout.write(line)
                     # Force le vidage du tampon pour un affichage instantané
                     sys.stdout.flush()
                     file.write('   ("' + line[0:19] + '", ' + str(size) + "),\n")
      except KeyboardInterrupt:
         # Permet de quitter proprement avec Ctrl+C
         file.write("]\n")
         sys.exit(0)

if __name__ == "__main__":
      filter_stdout()
