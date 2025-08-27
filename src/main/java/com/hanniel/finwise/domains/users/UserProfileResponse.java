package com.hanniel.finwise.domains.users;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

public record UserProfileResponse (
    UUID uuid,
    String name,
    String lastName,
    int age,
    String occupation,
    BigDecimal salary,
    BigDecimal fixedIncome,
    BigDecimal monthlyBudget,
    Currency defaultCurrency,
    RiskProfile riskProfile,
    LocalDateTime createdAt,
    LocalDateTime updatedAt,
    boolean accountActive
) {}
