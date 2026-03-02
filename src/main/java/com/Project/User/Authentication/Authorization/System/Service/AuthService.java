package com.Project.User.Authentication.Authorization.System.Service;

import com.Project.User.Authentication.Authorization.System.Model.RefreshToken;
import com.Project.User.Authentication.Authorization.System.Model.Role;
import com.Project.User.Authentication.Authorization.System.Model.User;
import com.Project.User.Authentication.Authorization.System.Repo.RoleRepository;
import com.Project.User.Authentication.Authorization.System.Repo.UserRepository;
import com.Project.User.Authentication.Authorization.System.dto.AuthResponse;
import com.Project.User.Authentication.Authorization.System.dto.LoginRequest;
import com.Project.User.Authentication.Authorization.System.dto.RegisterRequest;
import com.Project.User.Authentication.Authorization.System.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
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
                .build();
        userRepository.save(user);
    }
    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {

        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();
        String deviceInfo = httpRequest.getHeader("User-Agent");
        String ipAddress = httpRequest.getRemoteAddr();
        String accessToken = jwtService.generateToken(user.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user,deviceInfo,ipAddress);
        return new AuthResponse(accessToken, refreshToken.getToken());
    }
}
