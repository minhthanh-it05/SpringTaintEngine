package com.thanh.springtaint.structure;

import java.util.List;

public record ParameterInfo(String name, String type, List<String> annotations) {
}
