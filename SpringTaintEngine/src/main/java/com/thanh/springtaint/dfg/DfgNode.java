package com.thanh.springtaint.dfg;

public record DfgNode(int id, Kind kind, String variableName, String label) {

    public enum Kind {
        PARAM, ASSIGN, CALL, EXPRESSION, RETURN, MERGE, VALIDATED
    }
}