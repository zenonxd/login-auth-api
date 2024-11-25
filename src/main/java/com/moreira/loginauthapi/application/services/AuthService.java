package com.moreira.loginauthapi.application.services;

import com.moreira.loginauthapi.application.dto.LoginRequestDTO;
import com.moreira.loginauthapi.application.dto.LoginResponseDTO;
import com.moreira.loginauthapi.domain.entities.User;
import com.moreira.loginauthapi.domain.repositories.UserRepository;
import com.moreira.loginauthapi.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    TokenService tokenService;

    public LoginResponseDTO authenticate(LoginRequestDTO requestDTO) {
        User user = userRepository.findByEmail(requestDTO.email())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        if (!passwordEncoder.matches(requestDTO.password(), user.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }

        String token = tokenService.generateToken(user);
        return new LoginResponseDTO(user.getName(), token);
    }
}
