package com.moreira.loginauthapi.domain.repositories;

import com.moreira.loginauthapi.domain.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, String> {
    Role findRoleByName(String roleUser);

    Role findByName(String role);
}
