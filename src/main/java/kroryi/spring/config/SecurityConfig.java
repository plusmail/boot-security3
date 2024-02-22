package kroryi.spring.config;

import kroryi.spring.handler.OAuthLoginFailureHandler;
import kroryi.spring.handler.OAuthLoginSuccessHandler;
import kroryi.spring.service.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private OAuthLoginSuccessHandler oAuthLoginSuccessHandler;

    @Autowired
    private OAuthLoginFailureHandler oAuthLoginFailureHandler;

    @Autowired
    private MemberService memberService;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(configurer -> configurer.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .authorizeHttpRequests(registry ->
                        registry.requestMatchers("/user/**").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                )
                .formLogin(configurer ->
                        configurer.loginPage("/login")
                                .loginProcessingUrl("/loginProc")
                                .defaultSuccessUrl("/")
                )
                .oauth2Login(configurer -> configurer
                        .loginPage("/login") // google login page와 로그인 페이지를 맵핑 시켜줍니다.
                        .userInfoEndpoint(config -> config.userService(memberService))
                        .redirectionEndpoint(Customizer.withDefaults())
                        .successHandler(oAuthLoginSuccessHandler)
                        .failureHandler(oAuthLoginFailureHandler)
                );
        return http.build();
    }
}
