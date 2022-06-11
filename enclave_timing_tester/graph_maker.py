import matplotlib.pyplot as plt
from typing import List


amount0fBufReads: List[int] = [5000, 10000, 15000, 20000, 25000, 30000]
# The timings are made by considering 9 timing and taking the average of it
# These calculations have been made in an Excel sheet (and therefore not in this script!)
oldApproachTimings: List[float] = [1.87889, 4.40778, 6.29778, 8.35667, 10.52778, 12.45889]
newApproachTimings: List[float] = [2.13556, 4.15556, 6.26000, 8.40889, 10.78333, 12.77667]

plt.plot(amount0fBufReads, oldApproachTimings, label = "Old EDP code")
plt.plot(amount0fBufReads, newApproachTimings, label = "Modified EDP code")
plt.title("Performance of the entry code for repeated usercalls (lower is better).", fontsize="xx-large")
plt.xlabel("Amount of BufReads", fontsize="x-large")
plt.ylabel("Time (s)", fontsize="x-large")
plt.legend(fontsize="x-large")
# plt.grid(True) # To show grid lines
plt.subplots_adjust(left=0.06, right=0.97, top=0.93, bottom=0.08) # Discard large borders around plot
plt.show()
