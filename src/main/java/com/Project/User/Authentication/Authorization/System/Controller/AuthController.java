package com.Project.User.Authentication.Authorization.System.Controller;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import com.Project.User.Authentication.Authorization.System.Repo.RefreshTokenRepository;
import com.Project.User.Authentication.Authorization.System.Service.AuthService;
import com.Project.User.Authentication.Authorization.System.Service.RefreshTokenService;
import com.Project.User.Authentication.Authorization.System.dto.AuthResponse;
import com.Project.User.Authentication.Authorization.System.dto.LoginRequest;
import com.Project.User.Authentication.Authorization.System.dto.RegisterRequest;
import com.Project.User.Authentication.Authorization.System.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok("User registered successfully");
    }
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, httpRequest));
    }
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(
            @RequestParam String refreshToken,
            HttpServletRequest request) {
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken).orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        refreshTokenService.verifyExpiration(token);
        String currentDevice = request.getHeader("User-Agent");
        String currentIp = request.getRemoteAddr();
        if (!token.getDeviceInfo().equals(currentDevice) ||
                !token.getIpAddress().equals(currentIp)) {
            throw new RuntimeException("Suspicious refresh attempt detected");
        }
        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(token);
        String newAccessToken =
                jwtService.generateToken(
                        newRefreshToken.getUser().getUsername()
                );
        return ResponseEntity.ok(new AuthResponse(newAccessToken,newRefreshToken.getToken()));
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken) {
        refreshTokenService.deleteByToken(refreshToken);
        return ResponseEntity.ok("Logged out successfully");
    }
}
