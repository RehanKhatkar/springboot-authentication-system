package com.Project.User.Authentication.Authorization.System.config;

import com.Project.User.Authentication.Authorization.System.Model.Role;
import com.Project.User.Authentication.Authorization.System.Repo.RoleRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DataInitializer {

    private final RoleRepository roleRepository;

    @PostConstruct
    public void init() {

        if(roleRepository.findByName("ROLE_USER").isEmpty()){
            roleRepository.save(Role.builder().name("ROLE_USER").build());
        }

        if(roleRepository.findByName("ROLE_ADMIN").isEmpty()){
            roleRepository.save(Role.builder().name("ROLE_ADMIN").build());
        }
    }
}