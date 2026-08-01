package com.thanh.springtaint.report;

import com.thanh.springtaint.detect.Vulnerability;

import java.util.List;

public interface Reporter {
    String render(List<Vulnerability> vulnerabilities);
}
