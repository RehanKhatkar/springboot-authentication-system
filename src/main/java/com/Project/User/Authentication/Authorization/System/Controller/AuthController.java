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
import org.springframework.security.crypto.password.PasswordEncoder;
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
    private final PasswordEncoder passwordEncoder;
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
        return ResponseEntity.ok(authService.refreshToken(refreshToken, request));
    }
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestParam String refreshToken) {
        refreshTokenService.deleteByToken(refreshToken);
        return ResponseEntity.ok("Logged out successfully");
    }
}
