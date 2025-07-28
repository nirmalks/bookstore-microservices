package security;



import common.AppConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtUtils {
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(AppConstants.JWT_SECRET_KEY.getBytes(StandardCharsets.UTF_8));
    public static String extractUsername(String token) {
        return (String) getClaims(token).get("username");
    }

    public static String extractAuthorities(String token) {
        return (String) getClaims(token).get("authorities");
    }
    public static boolean validateToken(String token) {
        try {
            getClaims(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
    private static Claims getClaims(String token) {
        JwtParser parser = Jwts.parser()
                .verifyWith(SECRET_KEY)
                .build();

        return parser.parseSignedClaims(token).getPayload();
    }

    public static String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        return Jwts.builder().issuer("nirmalks").subject("token")
                .claim("username", username)
                .claim("role", authorities.stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.joining())
                )
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + 30000000))
                .signWith(SECRET_KEY)
                .compact();
    }
}
