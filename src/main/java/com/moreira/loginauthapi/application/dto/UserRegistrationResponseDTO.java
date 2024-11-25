package com.moreira.loginauthapi.application.dto;

import com.moreira.loginauthapi.domain.entities.Role;

import java.util.Set;

public record UserRegistrationResponseDTO(String id,
                                          String name,
                                          String email,
                                          String password,
                                          String token) {
}
