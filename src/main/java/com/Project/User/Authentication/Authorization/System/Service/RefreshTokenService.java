package com.Project.User.Authentication.Authorization.System.Service;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import com.Project.User.Authentication.Authorization.System.Model.User;
import com.Project.User.Authentication.Authorization.System.Repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;

    public String createRefreshToken(User user, String deviceInfo, String ipAddress) {
        refreshTokenRepository.findByUser(user).ifPresent(refreshTokenRepository::delete);
        String rawToken = UUID.randomUUID().toString();
        String hashedToken = passwordEncoder.encode(rawToken);
        RefreshToken refreshToken = RefreshToken.builder()
                .token(hashedToken)
                .user(user)
                .expiryDate(Instant.now().plusSeconds(604800))
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .build();
        refreshTokenRepository.save(refreshToken);
        return rawToken;
    }
    public void verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            throw new RuntimeException("Refresh token expired");
        }
    }
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }
    public String rotateRefreshToken(RefreshToken oldToken, String deviceInfo, String ipAddress) {
        refreshTokenRepository.delete(oldToken);
        return createRefreshToken(
                oldToken.getUser(),
                deviceInfo,
                ipAddress
        );
    }
}
