package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.sql.SQLException;
import java.sql.Statement;

@RestController
public class PaymentController {

    private final Statement statement;
    private final RestTemplate restTemplate;

    public PaymentController(Statement statement, RestTemplate restTemplate) {
        this.statement = statement;
        this.restTemplate = restTemplate;
    }

    // Demonstrates the new Sanitizer modeling (B1): the id is coerced through
    // Integer.parseInt before reaching the JDBC sink, so this must NOT be reported even
    // though it has the exact same shape as the SQL Injection findings elsewhere.
    @GetMapping("/payments")
    public String getPayment(@RequestParam String id) throws SQLException {
        int numericId = Integer.parseInt(id);
        String query = "SELECT * FROM payments WHERE id = " + numericId;
        return statement.executeQuery(query).toString();
    }

    // Demonstrates a new Sink category (B5): SSRF via RestTemplate, driven directly by an
    // attacker-controlled callback URL.
    @GetMapping("/payments/webhook")
    public String notifyWebhook(@RequestParam String callbackUrl) {
        return restTemplate.getForObject(callbackUrl, String.class);
    }
}
