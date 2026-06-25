import io.jsonwebtoken.Claims;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.ArrayList;
import java.util.List;

// ... (Các phần khác giữ nguyên, cập nhật đoạn logic xử lý try-catch bên dưới)

        try {
            String authHeader = request.getHeader("Authorization");

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);

                // Sử dụng ParserBuilder (Chuẩn cú pháp mới, tránh Deprecated trên Spring Boot 3.x)
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(SECRET_KEY.getBytes()) // Nên convert chuỗi secret sang dạng byte array
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                
                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    
                    // 1. Trích xuất Role và Tier đã được mã hóa trong payload của Token
                    String role = claims.get("role", String.class);               // Trả về: CUSTOMER, DRIVER, ADMIN
                    String customerTier = claims.get("customer_tier", String.class); // Trả về: REGULAR, VIP, hoặc null

                    // 2. Chuyển đổi thông tin thành danh sách Quyền hợp lệ trong Spring Security
                    List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    if (role != null) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                    
                    // Nếu là Khách hàng, nạp thêm Quyền theo hạng (Tier) để phục vụ logic tính phí VIP
                    if ("CUSTOMER".equals(role) && customerTier != null) {
                        authorities.add(new SimpleGrantedAuthority("TIER_" + customerTier)); 
                        // Sẽ sinh ra: TIER_REGULAR hoặc TIER_VIP
                    }

                    // 3. Đưa danh sách authorities (thay vì emptyList) vào Authentication Token
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    username,
                                    null,
                                    authorities
                            );

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }

            filterChain.doFilter(request, response);

        } // ... (Các block catch giữ nguyên logic ghi lỗi JSON rất tốt của bạn)