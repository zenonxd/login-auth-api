package com.moreira.loginauthapi.presentation.controllers;

import com.moreira.loginauthapi.application.dto.LoginRequestDTO;
import com.moreira.loginauthapi.application.dto.LoginResponseDTO;
import com.moreira.loginauthapi.application.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/auth")
public class AuthController {

    @Autowired
    private AuthService authService;


    @PostMapping(value = "/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequestDTO) {
        LoginResponseDTO response = authService.authenticate(loginRequestDTO);

        return ResponseEntity.ok(response);
    }

}
