package guddo.service;

import guddo.domain.User;
import guddo.domain.enums.Role;
import guddo.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request) {
        OAuth2User oAuth2User = super.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId().toUpperCase();
        String providerId = oAuth2User.getAttribute("sub");
        String email = oAuth2User.getAttribute("email");
        String firstname = oAuth2User.getAttribute("given_name");
        String lastname = oAuth2User.getAttribute("family_name");

        Optional<User> existingUser = userRepository.findByProviderAndProviderId(provider, providerId);

        User user;
        if (existingUser.isEmpty()) {

            user = User.builder()
                    .firstname(firstname)
                    .lastname(lastname)
                    .email(email)
                    .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .role(Role.USER)
                    .enabled(true)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            userRepository.save(user);
        } else {
            user = existingUser.get();
        }

        return new DefaultOAuth2User(
                user.getAuthorities(),
                oAuth2User.getAttributes(),
                "email"
        );
    }
}
