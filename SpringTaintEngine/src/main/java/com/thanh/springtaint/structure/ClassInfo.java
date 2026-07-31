package com.thanh.springtaint.structure;

import java.util.List;

public record ClassInfo(String name, List<String> annotations, List<MethodInfo> methods) {
}
