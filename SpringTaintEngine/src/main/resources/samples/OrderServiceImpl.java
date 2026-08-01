package com.example.demo;

import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.sql.Statement;

@Service
public class OrderServiceImpl implements OrderService {

    private final Statement statement;

    public OrderServiceImpl(Statement statement) {
        this.statement = statement;
    }

    @Override
    public String findOrder(String orderId) {
        try {
            String sql = "SELECT * FROM orders WHERE id = " + orderId;
            return statement.executeQuery(sql).toString();
        } catch (SQLException e) {
            return "error";
        }
    }
}
