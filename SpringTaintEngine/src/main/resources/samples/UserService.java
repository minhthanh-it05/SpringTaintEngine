package com.example.demo;

import org.springframework.stereotype.Service;

import java.sql.Statement;

@Service
public class UserService {

    private final Statement statement;

    public UserService(Statement statement) {
        this.statement = statement;
    }

    public String findByName(String name) throws Exception {
        String sql = "SELECT * FROM users WHERE name = " + name;
        return statement.executeQuery(sql).toString();
    }
}
