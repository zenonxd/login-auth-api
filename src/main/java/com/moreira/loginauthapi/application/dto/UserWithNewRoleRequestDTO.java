package com.moreira.loginauthapi.application.dto;

import com.moreira.loginauthapi.domain.entities.Role;

import java.util.Set;

public record UserWithNewRoleRequestDTO(Set<String> roles) {
}
