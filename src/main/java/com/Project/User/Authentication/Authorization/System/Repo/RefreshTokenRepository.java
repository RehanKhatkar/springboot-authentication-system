package com.Project.User.Authentication.Authorization.System.Repo;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long>{
    Optional<RefreshToken> findByToken(String token);
    void deleteByUserId(java.util.UUID userId);
    void deleteByToken(String token);
}
