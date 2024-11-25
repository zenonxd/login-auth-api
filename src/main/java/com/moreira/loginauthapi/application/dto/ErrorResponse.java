package com.moreira.loginauthapi.application.dto;

import java.time.LocalDate;
import java.time.LocalDateTime;

public record ErrorResponse(String message,
                            String details,
                            int status,
                            LocalDateTime timestamp,
                            String errorCode) {
}
