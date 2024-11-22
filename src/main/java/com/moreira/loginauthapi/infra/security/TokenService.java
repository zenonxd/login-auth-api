package com.moreira.loginauthapi.infra.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.moreira.loginauthapi.domain.entities.User;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    public String generateToken(User user) {

        try {

            Algorithm algorithm = Algorithm.HMAC256();

        } catch (JWTCreationException e) {
            throw new RuntimeException("Error while authenticating user");
        }

    }
}
