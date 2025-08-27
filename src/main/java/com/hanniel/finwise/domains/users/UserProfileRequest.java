package com.hanniel.finwise.domains.users;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

import java.math.BigDecimal;

public record UserProfileRequest (
        @NotBlank String name,
        @NotBlank String lastName,
        @Min(13) int age,
        String occupation,
        @DecimalMin("0.00")BigDecimal salary,
        @DecimalMin("0.00") BigDecimal fixedIncome,
        @DecimalMin("0.00") BigDecimal monthlyBudget,
        Currency defaultCurrency,
        RiskProfile riskProfile
        ) {}
