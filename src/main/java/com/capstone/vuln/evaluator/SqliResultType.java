package com.capstone.vuln.evaluator;

public enum SqliResultType {
    NORMAL,
    SQL_ERROR_EXPOSED,
    UNION_DATA_LEAKED,
    TIME_BASED_DELAY,
    LENGTH_ANOMALY,
    UNKNOWN
}