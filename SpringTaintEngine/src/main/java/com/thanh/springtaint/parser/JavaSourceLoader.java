package com.thanh.springtaint.parser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class JavaSourceLoader {
    public String load(Path filePath) throws IOException {
        return Files.readString(filePath);
    }
}
