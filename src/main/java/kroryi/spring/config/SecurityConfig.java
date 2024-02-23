package kroryi.spring.config;

import kroryi.spring.component.CustomAccessDeniedHandler;
import kroryi.spring.component.CustomAuthenticationEntryPoint;
import kroryi.spring.handler.OAuthLoginFailureHandler;
import kroryi.spring.handler.OAuthLoginSuccessHandler;
import kroryi.spring.jwt.JwtAuthFilter;
import kroryi.spring.jwt.JwtUtil;
import kroryi.spring.jwt.RefreshTokenRepository;
import kroryi.spring.oauth2.OAuth2AuthorizationRequestBasedOnCookieRepository;
import kroryi.spring.repository.MemberRepository;
import kroryi.spring.service.CustomUserDetailsService;
import kroryi.spring.service.MemberService;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@NoArgsConstructor(force = true)
public class SecurityConfig {


    private final OAuthLoginFailureHandler oAuthLoginFailureHandler;

    @Autowired
    private MemberService memberService;

    private final CustomUserDetailsService customUserDetailsService;

    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final RefreshTokenRepository refreshTokenRepository;

    private final MemberRepository memberRepository;
    private final ModelMapper modelMapper;
    private final JwtUtil jwtUtil;


    private static final  String[] AUTH_WHITELIST={
           "/", "/api/v1/member/**","/api/v1/auth/**"
    };
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)

                //JWT사용시에는 세션 사용 않함.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(registry ->
                        registry
                                .requestMatchers(AUTH_WHITELIST).permitAll()
                                .requestMatchers("/user/**").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                )
                .formLogin(AbstractHttpConfigurer::disable)
                .oauth2Login(configurer -> configurer
                        .loginPage("/login") // google login page와 로그인 페이지를 맵핑 시켜줍니다.
                        .authorizationEndpoint(author->author
                                .authorizationRequestRepository(oAuth2AuthorizationRequestBasedOnCookieRepository()))
                        .userInfoEndpoint(config -> config.userService(memberService))
                        .redirectionEndpoint(Customizer.withDefaults())
                        .successHandler(oAuth2SuccessHandler())
                        .failureHandler(oAuthLoginFailureHandler)
                );

        http.exceptionHandling(except->except.authenticationEntryPoint(customAuthenticationEntryPoint)
                .accessDeniedHandler(customAccessDeniedHandler));

        http.addFilterBefore(
                new JwtAuthFilter(jwtUtil),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OAuthLoginSuccessHandler oAuth2SuccessHandler() {
        return new OAuthLoginSuccessHandler();
    }

    @Bean
    public OAuth2AuthorizationRequestBasedOnCookieRepository oAuth2AuthorizationRequestBasedOnCookieRepository() {
        return new OAuth2AuthorizationRequestBasedOnCookieRepository();
    }
}
