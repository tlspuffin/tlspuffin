import argparse
from datetime import datetime
import numpy as np
from scipy.optimize import curve_fit


def process_measurements(file_path):
   # 1. import a campaign
   measurements = []
   with open(file_path, 'r', encoding='utf-8') as file:
      for line in file:
          comma = line.find(", ")
          measurements += [(line[0:comma], int(line[comma+2:-1]))]

   # 2. experimental data
   t_raw_data = []
   a_raw_data = []
   T_ini = datetime.fromisoformat(measurements[0][0]).timestamp() / 3600.0
   A_inf = measurements[-1][1] # asymptotic value
   T_0 = 0
   for (t, a) in measurements:
      if a > A_inf / 2:
         if T_0 == 0:
            T_0 = datetime.fromisoformat(t).timestamp() / 3600.0
            R_0 = A_inf - a
         t_raw_data += [datetime.fromisoformat(t).timestamp() / 3600.0 - T_0]
         a_raw_data += [a]
   t_data = np.array(t_raw_data)
   a_data = np.array(a_raw_data)

   print(file_path + ", " + measurements[0][0])
   print("t: " + str(t_data))
   print("a: " + str(a_data))

   # 3. Theoretical model
   def model(t, k):
      return A_inf - R_0 * np.exp(-k * t)

   # 5. Fitting using the non-linear least squares method
   parameters, covariance = curve_fit(model, t_data, a_data, p0=[1])

   # 6. Results
   k_optimal = parameters[0]
   uncertainties = np.sqrt(np.diag(covariance))
   k_uncertainty = uncertainties[0]
   print(f"k : {k_optimal:.3f} ± {k_uncertainty:.3f} (en h^-1)")

   # 7. Typical time to have less than 1% variation
   error = 0.1 # %
   tau = -1/k_optimal * np.log(error/100*A_inf/R_0)
   t = T_0 - T_ini + tau
   print(f"t_0: %i min" % ((T_0 - T_ini)* 60.0))
   print(f"Convergence time (<{error:.1f} %): {tau:.1f} h")
   print(f"total time: {t:.1f} h")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Estimate convergence time...")
    parser.add_argument("filename", help="Path of the meausurements file")
    args = parser.parse_args()
    process_measurements(args.filename)
