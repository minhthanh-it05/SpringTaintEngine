package com.thanh.springtaint.structure;

import java.util.List;

public record MethodInfo(String name, String returnType, List<ParameterInfo> parameters, List<String> annotations) {
}
