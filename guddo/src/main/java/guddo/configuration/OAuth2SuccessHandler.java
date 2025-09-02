package guddo.configuration;

import guddo.domain.User;
import guddo.repository.UserRepository;
import guddo.service.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();


        String email = oAuth2User.getAttribute("email");

        User user;
        if (email != null) {

            user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalStateException("User not found after Google login"));
        } else {

            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String provider = oauthToken.getAuthorizedClientRegistrationId().toUpperCase();
            String providerId = oAuth2User.getName();

            user = userRepository.findByProviderAndProviderId(provider, providerId)
                    .orElseThrow(() -> new IllegalStateException("User not found after Google login"));
        }

        String jwt = jwtService.generateToken(user);


        response.setContentType("application/json");
        response.getWriter().write(jwt);
    }
}
