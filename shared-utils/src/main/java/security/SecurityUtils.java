package security;

import org.springframework.security.crypto.password.PasswordEncoder;

public class SecurityUtils {
    public static String encode(String rawPassword, PasswordEncoder passwordEncoder) {
        return passwordEncoder.encode(rawPassword);
    }

    public static boolean matches(String rawPassword, String encodedPassword, PasswordEncoder passwordEncoder) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
