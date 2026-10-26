# S4-2 지시서 2 기대값 독립 교차검증 (ADR-S4-01 R3 Wilson, R11 Hyndman-Fan type 8)
import numpy as np, statsmodels, statsmodels.stats.proportion as sp
print("numpy", np.__version__, "statsmodels", statsmodels.__version__)
m = "median_unbiased"   # Hyndman-Fan type 8
print("t8 {1..20} p50,p95:", np.quantile(np.arange(1, 21), [0.5, 0.95], method=m))
print("t8 {1..5} p95:", np.quantile([1, 2, 3, 4, 5], 0.95, method=m))
print("t8 {7} p30:", np.quantile([7], 0.3, method=m))
for x, n in [(20, 20), (80, 80), (0, 73), (10, 20)]:
    lo, hi = sp.proportion_confint(x, n, alpha=0.05, method="wilson")
    print(f"wilson {x}/{n}: lo={lo:.6f} hi={hi:.6f}")

