package com.hanniel.finwise.domains.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum Role {
    ADMIN("admin"),
    USER("user");

    private final String role;

    Role(String role){
        this.role = role;
    }

    @JsonValue
    public String getRole(){
        return role;
    }

    @JsonCreator
    public static Role from(String value) {
        if (value == null) return USER;
        String v = value.trim();

        for (Role r : values()) {
            if (r.name().equalsIgnoreCase(v) || r.role.equalsIgnoreCase(v)) {
                return r;
            }
        }
        throw new IllegalArgumentException("Invalid role: " + value);
    }
}
