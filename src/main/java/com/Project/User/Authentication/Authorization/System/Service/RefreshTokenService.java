package com.Project.User.Authentication.Authorization.System.Service;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import com.Project.User.Authentication.Authorization.System.Model.User;
import com.Project.User.Authentication.Authorization.System.Repo.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;
    public RefreshToken createRefreshToken(User user, String deviceInfo, String ipAddress) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().plusSeconds(604800))
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .build();
        return refreshTokenRepository.save(refreshToken);
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
    public RefreshToken rotateRefreshToken(RefreshToken oldToken) {
        refreshTokenRepository.delete(oldToken);
        return createRefreshToken(oldToken.getUser(), oldToken.getDeviceInfo(), oldToken.getIpAddress());
    }
}
