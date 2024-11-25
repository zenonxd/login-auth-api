package com.moreira.loginauthapi.presentation.controllers;

import com.moreira.loginauthapi.application.dto.*;
import com.moreira.loginauthapi.application.services.UserService;
import com.moreira.loginauthapi.domain.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.nio.file.AccessDeniedException;

@RestController
@RequestMapping(value = "/users")
public class UserController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserRegistrationResponseDTO> createUser(@RequestBody UserRegistrationRequestDTO userRegistrationRequestDTO) {

        UserRegistrationResponseDTO responseDTO = userService.createUser(userRegistrationRequestDTO);

        URI uri = ServletUriComponentsBuilder
                .fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(responseDTO.id())
                .toUri();

        return ResponseEntity.created(uri).body(responseDTO);
    }

    @PreAuthorize("hasRole('COMMON')")
    @GetMapping
    public ResponseEntity<Page<UserPageableResponseDTO>> findAllPageable(Pageable pageable) {
        Page<UserPageableResponseDTO> users = userService.findAllPageable(pageable);

        return ResponseEntity.ok(users);
    }

    @PreAuthorize("hasRole('COMMON')")
    @GetMapping(value = "/{id}")
    public ResponseEntity<UserInformationsResponseDTO> findById(@PathVariable String id) {
        UserInformationsResponseDTO response = userService.findById(id);

        return ResponseEntity.ok(response);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value = "/{id}")
    public ResponseEntity<UserChangesResponseDTO> update(@PathVariable String id, @RequestBody UserChangesRequestDto userChangesRequestDto) {
        UserChangesResponseDTO userChanged = userService.update(id, userChangesRequestDto);

        return ResponseEntity.ok(userChanged);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping(value = "/insert-role/{id}")
    public ResponseEntity<UserWithNewRoleResponseDTO> insertRoleOnUser(@PathVariable String id,
                                                                      @RequestBody UserWithNewRoleRequestDTO userWithNewRoleRequestDTO) throws AccessDeniedException {

        UserWithNewRoleResponseDTO userWithNewRole = userService.insertRoleOnUser(id, userWithNewRoleRequestDTO);

        return ResponseEntity.ok(userWithNewRole);

    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping(value = "{id}")
    public ResponseEntity<Void> deleteById(@PathVariable String id) {
        userService.deleteById(id);

        return ResponseEntity.noContent().build();
    }

}
