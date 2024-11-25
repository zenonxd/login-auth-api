package com.moreira.loginauthapi.application.services;

import com.moreira.loginauthapi.application.dto.*;
import com.moreira.loginauthapi.domain.entities.Role;
import com.moreira.loginauthapi.domain.entities.User;
import com.moreira.loginauthapi.domain.repositories.RoleRepository;
import com.moreira.loginauthapi.domain.repositories.UserRepository;
import com.moreira.loginauthapi.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    TokenService tokenService;

    @Autowired
    private RoleRepository roleRepository;

    public UserRegistrationResponseDTO createUser(UserRegistrationRequestDTO userRegistrationRequestDTO) {
        //antes de tudo, chegar se email já existe no banco de dados, se sim, continua

        User user = new User();
        //adicionar validações para exceção
        user.setName(userRegistrationRequestDTO.name());
        user.setEmail(userRegistrationRequestDTO.email());
        user.setPassword(passwordEncoder.encode(userRegistrationRequestDTO.password()));

        //lembrar de arrumar no SecurityConfig os endpoints com as roles

        //role principal
        Role primaryRole = roleRepository.findByName(userRegistrationRequestDTO.role());
        user.setPrimaryRole(primaryRole);


        //adiciona role principal na lista de roles
        user.getRoles().add(primaryRole);

        userRepository.save(user);

        String token = tokenService.generateToken(user);

        return new UserRegistrationResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPassword(),
                user.getRoles(),
                token
        );
    }

    public Page<UserPageableResponseDTO> findAllPageable(Pageable pageable) {
        Page<User> users = userRepository.findAll(pageable);

        List<UserPageableResponseDTO> usersDtos = users.getContent().stream()
                .map(user -> new UserPageableResponseDTO(user.getId(), user.getName(), user.getEmail()))
                .collect(Collectors.toList());

        return new PageImpl<>(usersDtos, pageable, users.getTotalElements());
    }

    public UserChangesResponseDTO update(String id, UserChangesRequestDto userChangesRequestDto) {
        //implementar metodo para buscar por ID lançando exceção automaticamente
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        user.setName(userChangesRequestDto.name());
        user.setEmail(userChangesRequestDto.email());
        userRepository.save(user);

        return new UserChangesResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail()
        );
    }

    public UserInformationsResponseDTO findById(String id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return new UserInformationsResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRoles());
    }

    public void deleteById(String id) {
        userRepository.deleteById(id);
    }
}
