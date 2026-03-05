package com.Project.User.Authentication.Authorization.System.Service;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import com.Project.User.Authentication.Authorization.System.Model.Role;
import com.Project.User.Authentication.Authorization.System.Model.User;
import com.Project.User.Authentication.Authorization.System.Repo.RefreshTokenRepository;
import com.Project.User.Authentication.Authorization.System.Repo.RoleRepository;
import com.Project.User.Authentication.Authorization.System.Repo.UserRepository;
import com.Project.User.Authentication.Authorization.System.dto.AuthResponse;
import com.Project.User.Authentication.Authorization.System.dto.LoginRequest;
import com.Project.User.Authentication.Authorization.System.dto.RegisterRequest;
import com.Project.User.Authentication.Authorization.System.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 15;
    public void register(RegisterRequest request){
        if(userRepository.findByUsername(request.getUsername()).isPresent()){
            throw new RuntimeException("Username already exists");
        }
        Role userRole=roleRepository.findByName("ROLE_USER").orElseThrow(()->new RuntimeException("Role not found"));
        User user=User.builder()
                .id(UUID.randomUUID())
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .enabled(true)
                .createdAt(LocalDateTime.now())
                .failedAttempts(0)
                .locked(false)
                .build();
        userRepository.save(user);
    }
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        if (user.isLocked()) {
            if (!unlockWhenTimeExpired(user)) {
                throw new RuntimeException("Account locked. Try again later.");
            }
        }
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (BadCredentialsException ex) {
            log.warn("Failed login attempt for user: {}", request.getUsername());
            increaseFailedAttempts(user);
            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                lock(user);
                log.warn("User account locked due to multiple failed attempts: {}", user.getUsername());
            }
            throw new RuntimeException("Invalid username or password");
        }
        if (user.getFailedAttempts() > 0) {
            user.setFailedAttempts(0);
            userRepository.save(user);
        }
        String deviceInfo = httpRequest.getHeader("User-Agent");
        String ipAddress = httpRequest.getRemoteAddr();
        String accessToken = jwtService.generateToken(user.getUsername());
        String rawRefreshToken = refreshTokenService.createRefreshToken(user,deviceInfo,ipAddress);
        return new AuthResponse(accessToken,rawRefreshToken);
    }
    public AuthResponse refreshToken(@RequestParam String refreshToken, HttpServletRequest request){
        RefreshToken token = refreshTokenRepository.findAll()
                .stream()
                .filter(stored ->
                        passwordEncoder.matches(refreshToken, stored.getToken()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        refreshTokenService.verifyExpiration(token);
        String currentDevice = request.getHeader("User-Agent");
        String currentIp = request.getRemoteAddr();
        if (!token.getDeviceInfo().equals(currentDevice) ||
                !token.getIpAddress().equals(currentIp)) {
            throw new RuntimeException("Suspicious refresh attempt detected");
        }
        String newRawRefreshToken =
                refreshTokenService.rotateRefreshToken(
                        token,
                        currentDevice,
                        currentIp
                );
        String newAccessToken =
                jwtService.generateToken(
                        token.getUser().getUsername()
                );
        return new AuthResponse(newAccessToken, newRawRefreshToken);
    }
    private void increaseFailedAttempts(User user) {
        user.setFailedAttempts(user.getFailedAttempts() + 1);
        userRepository.save(user);
    }
    private void lock(User user) {
        user.setLocked(true);
        user.setLockedAt(LocalDateTime.now());
        userRepository.save(user);
    }
    private void unlock(User user) {
        user.setLocked(false);
        user.setFailedAttempts(0);
        user.setLockedAt(null);
        userRepository.save(user);
    }
    private boolean unlockWhenTimeExpired(User user) {
        if (user.getLockedAt() == null){
            return false;
        }
        LocalDateTime unlockTime = user.getLockedAt().plusMinutes(LOCK_TIME_DURATION);
        if (LocalDateTime.now().isAfter(unlockTime)) {
            unlock(user);
            return true;
        }
        return false;
    }
}
