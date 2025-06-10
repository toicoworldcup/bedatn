package org.example.doantn.Security;
import org.example.doantn.Repository.UserRepo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity

public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Kích hoạt CORS và sử dụng CorsConfigurationSource đã định nghĩa
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 2. Tắt CSRF nếu bạn đang xây dựng REST API không dùng session
                // Đối với các ứng dụng RESTful API sử dụng token (JWT), việc tắt CSRF thường là an toàn.
                .csrf(csrf -> csrf.disable())
                // 3. Cấu hình ủy quyền cho các request HTTP
                .authorizeHttpRequests(auth -> auth
                        // Cho phép tất cả các request OPTIONS (đặc biệt quan trọng cho preflight CORS)
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        // Cho phép truy cập công khai đến endpoint đăng nhập và các endpoint khác không cần xác thực
                        // Hãy điều chỉnh các đường dẫn này cho phù hợp với ứng dụng của bạn
                        .requestMatchers("/api/auth/**", "/public/**").permitAll()
                        // Yêu cầu xác thực cho tất cả các request khác
                        .anyRequest().authenticated()
                );
        // 4. Các cấu hình Spring Security khác của bạn có thể đặt ở đây
        // Ví dụ: .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // .exceptionHandling(...)
        // .authenticationProvider(...)

        return http.build();
    }




    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(List.of(authProvider));
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepo userRepository) {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // ĐẢM BẢO CHÍNH XÁC URL CỦA FRONTEND CỦA BẠN TRÊN VERCEL
        configuration.setAllowedOrigins(List.of("https://fedatn-r6fd.vercel.app"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*")); // Cho phép tất cả các headers
        configuration.setAllowCredentials(true); // Quan trọng nếu bạn dùng cookies/headers xác thực
        configuration.setMaxAge(3600L); // Thời gian sống của preflight request

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // Áp dụng cấu hình cho tất cả các đường dẫn
        return source;
    }

}