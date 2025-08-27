package com.hanniel.finwise.domains.users;

import com.hanniel.finwise.domains.auth.UserCredentials;
import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

@Table
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Setter
@Getter
public class UserProfile {

    @Id
    private UUID uuid;

    @OneToOne(fetch = FetchType.LAZY)
    @MapsId
    @JoinColumn(name = "id")
    private UserCredentials credentials;

    @NotBlank
    private String name;

    @NotBlank
    private String lastName;

    @Min(13)
    private int age;

    private String occupation;

    @DecimalMin("0.00")
    @Column(precision = 10, scale = 2)
    private BigDecimal salary;

    @DecimalMin("0.00")
    @Column(precision = 10, scale = 2)
    private BigDecimal fixedIncome;

    @DecimalMin("0.00")
    @Column(precision = 10, scale = 2)
    private BigDecimal monthlyBudget;

    @Enumerated(EnumType.STRING)
    private Currency defaultCurrency;

    @Enumerated(EnumType.STRING)
    private RiskProfile riskProfile;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private boolean accountActive = true;

    private LocalDateTime deactivatedAt;
}
