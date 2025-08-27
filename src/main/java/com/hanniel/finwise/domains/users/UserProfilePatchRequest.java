package com.hanniel.finwise.domains.users;

import java.math.BigDecimal;

public record UserProfilePatchRequest(
    String name,
    String lastName,
    Integer age,
    String occupation,
    BigDecimal salary,
    BigDecimal fixedIncome,
    BigDecimal monthlyBudget,
    Currency defaultCurrency,
    RiskProfile riskProfile
) {
}
