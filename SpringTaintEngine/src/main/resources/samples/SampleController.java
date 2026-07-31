package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Statement;

@RestController
public class SampleController {

    @GetMapping("/user")
    public String getUser(@RequestParam String id, Statement statement) throws Exception {
        if (id == null) {
            return "missing id";
        }
        String query = "SELECT * FROM users WHERE id = " + id;
        return statement.executeQuery(query).toString();
    }
}
