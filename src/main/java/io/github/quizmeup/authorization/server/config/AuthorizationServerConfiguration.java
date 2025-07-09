package io.github.quizmeup.authorization.server.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.quizmeup.authorization.server.service.FeignUserService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import java.time.Duration;
import java.util.UUID;

@Configuration
public class AuthorizationServerConfiguration {

    private static final String SIGN_IN_PAGE = "/login";

    @Bean
    public RegisteredClientRepository registeredClientRepository(final PasswordEncoder passwordEncoder) {
        final RegisteredClient serverClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("server")
                .clientName("server")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("read")
                .scope("write")
                .build();

        final RegisteredClient swaggerClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("swagger")
                .clientName("swagger")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://127.0.0.1:4000/swagger-ui/oauth2-redirect.html")
                .redirectUri("http://localhost:4000/swagger-ui/oauth2-redirect.html")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        final RegisteredClient administrationClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("administration")
                .clientName("administration")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://localhost:4200")
                .redirectUri("http://localhost:4200/callback")
                .redirectUri("http://localhost:4200/silent-refresh.html")
                .postLogoutRedirectUri("http://localhost:4200")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofDays(1))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false)
                        .build())
                .build();


        final RegisteredClient flutterClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("flutter-app")
                .clientName("flutter-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("com.example.app://oauth")
                .redirectUri("http://localhost:8080/auth-callback")
                .redirectUri("http://localhost:3000/callback")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofDays(36500)) // 100 years for long-lived refresh tokens
                        .build())
                .build();


        final RegisteredClient reactNative = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("react-native-app")
                .clientName("react-native-app")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://localhost:8081")
                .redirectUri("http://localhost:8082")
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        //.accessTokenTimeToLive(Duration.ofSeconds(10)) // 100 years for long-lived refresh tokens
                        .accessTokenTimeToLive(Duration.ofDays(36500)) // 100 years for long-lived refresh tokens
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(serverClient, swaggerClient, administrationClient, flutterClient, reactNative);
    }


    @Bean
    public AuthenticationManager authenticationManager(final FeignUserService feignUserService,
                                                       final PasswordEncoder passwordEncoder) {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(feignUserService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(authProvider);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> tokenGenerator(final JWKSource<SecurityContext> jwkSource,
                                                            final FeignUserService feignUserService) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtAccessTokenGenerator = new JwtGenerator(jwtEncoder);
        jwtAccessTokenGenerator.setJwtCustomizer(feignUserService);
        return new DelegatingOAuth2TokenGenerator(jwtAccessTokenGenerator);
    }

    @Bean
    @Order(3)
    public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http,
                                                                      @Qualifier("defaultCorsConfigurationSource") final CorsConfigurationSource corsConfigurationSource) throws Exception {
        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (auth2AuthorizationServerConfigurer) -> {
                    auth2AuthorizationServerConfigurer
                            .oidc(Customizer.withDefaults());
                })
                .oauth2ResourceServer(oAuth2ResourceServerConfigurer ->
                        oAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults())
                )
                .cors(corsConfigurer ->
                        corsConfigurer.configurationSource(corsConfigurationSource)
                )
                .exceptionHandling(exceptions ->
                        exceptions.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(SIGN_IN_PAGE),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          @Qualifier("defaultCorsConfigurationSource") final CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
                .cors(corsConfigurer ->
                        corsConfigurer.configurationSource(corsConfigurationSource)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers(
                                        "/login",
                                        "/register",
                                        "/oauth2/consent",
                                        "/error",
                                        "/oauth2/**",
                                        "/.well-known/**"
                                ).permitAll()
                                .anyRequest().authenticated()
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/login")
                                .permitAll()
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .loginPage("/login")
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain assetSecurityFilterChain(final HttpSecurity httpSecurity) throws Exception {
        final HttpSecurity assetHttp = httpSecurity.securityMatcher("/webjars/**", "/images/**", "/css/**", "/assets/**", "/favicon.ico");

        assetHttp
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                        .anyRequest().permitAll()
                );

        return assetHttp.build();
    }

    @Bean
    @Order(1)
    public SecurityFilterChain actuatorSecurityFilterChain(final HttpSecurity httpSecurity) throws Exception {
        final HttpSecurity actuatorHttp = httpSecurity.securityMatcher("/actuator/**");

        actuatorHttp
                        .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                                .anyRequest().permitAll()
                        );

        return actuatorHttp.build();
    }
}
