package com.thanh.springtaint.cfg;

public record CfgNode(int id, Kind kind, String label) {

    public enum Kind {
        ENTRY, EXIT, STATEMENT, CONDITION
    }
}
