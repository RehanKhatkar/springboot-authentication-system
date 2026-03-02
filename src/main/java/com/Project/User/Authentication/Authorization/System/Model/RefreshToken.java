package com.Project.User.Authentication.Authorization.System.Model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
    private Instant expiryDate;
    @Column(nullable = false)
    private String deviceInfo;
    @Column(nullable = false)
    private String ipAddress;
}
