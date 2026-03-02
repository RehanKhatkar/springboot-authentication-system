package com.Project.User.Authentication.Authorization.System.Repo;

import com.Project.User.Authentication.Authorization.System.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(String name);
}
