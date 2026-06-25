package com.delivery.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Khóa bí mật cấu hình hệ thống
    private final String SECRET_KEY = "rikkei_secret_key_super_secure_do_not_share";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {

                String token = authHeader.substring(7);

                // Tạo Signing Key chuẩn cấu trúc mật mã học của JJWT mới trên Spring Boot 3
                Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

                // Giải nén toàn bộ Claims (Payload) từ JWT bằng ParserBuilder mới
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    
                    // 1. Trích xuất thông tin Role và Thương mại Tier từ Token
                    String role = claims.get("role", String.class);               // Định dạng: CUSTOMER, DRIVER, ADMIN
                    String customerTier = claims.get("customer_tier", String.class); // Định dạng: REGULAR, VIP

                    // 2. Ánh xạ quyền (GrantedAuthority) tương thích với cấu trúc Spring Security
                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    
                    if (role != null) {
                        // Thêm tiền tố ROLE_ để sử dụng được các hàm mặc định như .hasRole("ADMIN")
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                    
                    // Nếu là khách hàng, nạp thêm thông tin phân hạng (Tier) để phục vụ logic tính toán phí giao hàng
                    if ("CUSTOMER".equals(role) && customerTier != null) {
                        authorities.add(new SimpleGrantedAuthority("TIER_" + customerTier)); // Sinh ra: TIER_REGULAR, TIER_VIP
                    }

                    // 3. Khởi tạo đối tượng xác thực chứa danh sách quyền thực tế (thay vì danh sách rỗng ban đầu)
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    authorities
                            );

                    // Đăng ký thông tin xác thực vào Context hệ thống
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException ex) {
            writeJsonError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "TOKEN_EXPIRED", "JWT token has expired");

        } catch (Exception ex) {
            writeJsonError(response, HttpServletResponse.SC_UNAUTHORIZED,
                    "INVALID_TOKEN", "JWT token is invalid");
        }
    }

    private void writeJsonError(HttpServletResponse response,
                                int status,
                                String code,
                                String message) throws IOException {

        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        body.put("error", code);
        body.put("message", message);

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}