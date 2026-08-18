from datetime import datetime
import numpy as np
from scipy.optimize import curve_fit

# 1. import a campaign
from convergence_bug_dead_session_05 import title, measurements

# 2. experimental data
t_raw_data = []
y_raw_data = []
start = datetime.fromisoformat(measurements[0][0]).timestamp()
for (t, y) in measurements:
   t_raw_data += [(datetime.fromisoformat(t).timestamp() - start) / 3600.0]
   y_raw_data += [y]
t_data = np.array(t_raw_data)
y_data = np.array(y_raw_data)

print(title + ", " + measurements[0][0])
print("t data: " + str(t_data))
print("y data: " + str(y_data))

# 3. Theoretical model
B = y_data[-1]
def model(t, A, k):
    return A * np.exp(-k * t) + B

# 5. Fitting using the non-linear least squares method
parametres, covariance = curve_fit(model, t_data, y_data, p0=[y_data[0] - B, 1])

# 6. Results
A_optimal, k_optimal = parametres
print(f"A : {A_optimal:.3f}")
print(f"k : {k_optimal:.3f}")

# 7. Typical time to have less than 1% variation
error = 0.1 # %
tau = -1/k_optimal * np.log(error/100*B/-A_optimal)
print(f"Convergence time (<{error:.1f} %): {tau:.1f} h") 
