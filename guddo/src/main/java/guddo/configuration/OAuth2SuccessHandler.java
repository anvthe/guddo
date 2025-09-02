package guddo.configuration;

import guddo.domain.User;
import guddo.domain.enums.Role;
import guddo.repository.UserRepository;
import guddo.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String firstname = oAuth2User.getAttribute("given_name");
        String lastname = oAuth2User.getAttribute("family_name");

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {

                    User newUser = User.builder()
                            .firstname(firstname != null ? firstname : "Unknown")
                            .lastname(lastname != null ? lastname : "")
                            .email(email)
                            .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                            .role(Role.USER)
                            .enabled(true)
                            .provider("GOOGLE")
                            .providerId(oAuth2User.getAttribute("sub"))
                            .build();
                    return userRepository.save(newUser);
                });


        String jwt = jwtService.generateToken(user);

        response.setContentType("application/json");
        response.getWriter().write(jwt);
    }
}
