package com.moreira.loginauthapi.application.services;

import com.moreira.loginauthapi.application.dto.*;
import com.moreira.loginauthapi.domain.entities.Role;
import com.moreira.loginauthapi.domain.entities.User;
import com.moreira.loginauthapi.domain.exceptions.EmailInUseException;
import com.moreira.loginauthapi.domain.exceptions.PasswordException;
import com.moreira.loginauthapi.domain.repositories.RoleRepository;
import com.moreira.loginauthapi.domain.repositories.UserRepository;
import com.moreira.loginauthapi.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.file.AccessDeniedException;
import java.util.*;
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

        if (userRepository.existsByEmail(userRegistrationRequestDTO.email())) {
            throw new EmailInUseException("Email already in use.");
        }

        if (userRegistrationRequestDTO.password().length() < 6) {
            throw new PasswordException("Password must be at least 6 characters.");
        }

        User user = new User();
        //adicionar validações para exceção
        user.setName(userRegistrationRequestDTO.name());
        user.setEmail(userRegistrationRequestDTO.email());
        user.setPassword(passwordEncoder.encode(userRegistrationRequestDTO.password()));

        user.setRole("ROLE_COMMON");

        //lembrar de arrumar no SecurityConfig os endpoints com as roles

        userRepository.save(user);

        String token = tokenService.generateToken(user);

        return new UserRegistrationResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getPassword(),
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
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

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
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new UserInformationsResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRoles());
    }

    public void deleteById(String id) {
        if (!userRepository.existsById(id)) {
            throw new UsernameNotFoundException("User not found.");
        }
        userRepository.deleteById(id);
    }

    @Secured(("ROLE_ADMIN"))
    public UserWithNewRoleResponseDTO insertRoleOnUser(String id, UserWithNewRoleRequestDTO userWithNewRoleRequestDTO) throws AccessDeniedException {

        if (!userRepository.existsById(id)) {
            throw new UsernameNotFoundException("User not found.");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"));

        if (!isAdmin) {
            throw new AccessDeniedException("You dont have the permission to do this action.");
        }

        User user = userRepository.getReferenceById(id);
        Set<Role> roles = new HashSet<>(roleRepository.findByNameIn(userWithNewRoleRequestDTO.roles()));

        user.getRoles().addAll(roles);

        userRepository.save(user);

        return new UserWithNewRoleResponseDTO(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
        );
    }
}
