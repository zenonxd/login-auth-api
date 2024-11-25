package com.moreira.loginauthapi.application.dto;

import com.moreira.loginauthapi.domain.entities.Role;

import java.util.Set;

public record UserWithNewRoleResponseDTO(String id,
                                         String name,
                                         String email,
                                         Set<String> roles) {
}
