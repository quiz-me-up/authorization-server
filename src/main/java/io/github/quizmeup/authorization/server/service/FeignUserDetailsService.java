package io.github.quizmeup.authorization.server.service;

import io.github.quizmeup.authorization.server.feign.UserFeignClient;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
public class FeignUserDetailsService implements UserDetailsService, OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger logger = LoggerFactory.getLogger(FeignUserDetailsService.class);

    private final UserFeignClient userFeignClient;

    public FeignUserDetailsService(UserFeignClient userFeignClient) {
        this.userFeignClient = userFeignClient;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            logger.debug("Loading user by username: {}", username);
            final UserFeignClient.UserResponse userResponse = userFeignClient.findUserByEmail(username);

            if (userResponse == null || userResponse.email() == null) {
                logger.warn("User not found: {}", username);
                throw new UsernameNotFoundException("User not found: " + username);
            }

            logger.debug("User found: {}", userResponse.email());

            return User
                    .withUsername(userResponse.email())
                    .password(userResponse.password())
                    .authorities(Collections.emptyList())
                    .accountExpired(false)
                    .accountLocked(false)
                    .credentialsExpired(false)
                    .disabled(false)
                    .build();

        } catch (Exception exception) {
            logger.error("Error loading user: {}", username, exception);
            throw new UsernameNotFoundException("User not found: " + username, exception);
        }
    }

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims(claims -> {
                try {
                    Object principal = context.getPrincipal().getPrincipal();

                    String email = null;
                    List<String> roles = Collections.emptyList();

                    if (principal instanceof UserDetails userDetails) {
                        email = userDetails.getUsername();
                    } else if (principal instanceof DefaultOidcUser oidcUser) {
                        email = oidcUser.getEmail();
                    }

                    if (StringUtils.isNotBlank(email)) {
                        claims.put("email", email);
                        claims.put("sub", email);
                        claims.put("preferred_username", email);
                    }

                    claims.put("roles", roles);
                    claims.put("authorities", roles);

                } catch (Exception exception) {
                    logger.error("Error customizing JWT token", exception);
                    claims.put("roles", Collections.emptyList());
                }
            });
        }
    }
}
