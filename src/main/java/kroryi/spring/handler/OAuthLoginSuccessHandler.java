package kroryi.spring.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kroryi.spring.dto.MemberDto;
import kroryi.spring.entity.Member;
import kroryi.spring.jwt.CookieUtil;
import kroryi.spring.jwt.JwtUtil;
import kroryi.spring.jwt.RefreshToken;
import kroryi.spring.jwt.RefreshTokenRepository;
import kroryi.spring.oauth2.OAuth2AuthorizationRequestBasedOnCookieRepository;
import kroryi.spring.repository.MemberRepository;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
@NoArgsConstructor(force = true)
public class OAuthLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    @Autowired
    private final RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private final MemberRepository memberRepository;
    @Autowired
    private final ModelMapper modelMapper;
    @Autowired
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    @Autowired
    private final JwtUtil jwtUtil;

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info("onAuthenticationSuccess1-> {}", token);

        log.info("onAuthenticationSuccess2-> {}",  authentication.getPrincipal());
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        log.info("onAuthenticationSuccess3-> {}",  ((Map<String, Object>)oAuth2User.getAttribute("kakao_account")).get("email").toString());

        String email = null;
        String oauthType = token.getAuthorizedClientRegistrationId();
        log.info("onAuthenticationSuccess4-> {}",  oauthType);

        email = switch (oauthType.toLowerCase()) {
            case "kakao" -> ((Map<String, Object>)token.getPrincipal().getAttribute("kakao_account")).get("email").toString();
            case "naver" -> ((Map<String, Object>)token.getPrincipal().getAttribute("response")).get("email").toString();
            case "google" -> token.getPrincipal().getAttribute("email").toString();
            default -> email;
        };

        Optional<Member> member = null;
        if (memberRepository != null) {
            member = Optional.ofNullable(memberRepository.findMemberByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("해당하는 Email이 없습니다.")));
        }

        if(member.isEmpty()){
            try {
                throw new Exception("존재하지 않는 email입니다. 다시 확인 하세요");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }else{
            String refreshToken = null;
            if (jwtUtil != null) {
                if (modelMapper != null) {
                    refreshToken = jwtUtil.createAccessToken(modelMapper.map(member, MemberDto.class));
                }
            }
            saveRefreshToken(member.get().getId(), refreshToken);
            addRefreshTokenToCookie(request, response, refreshToken);

            String accessToken = null;
            if (jwtUtil != null) {
                if (modelMapper != null) {
                    accessToken = jwtUtil.createAccessToken(modelMapper.map(member, MemberDto.class));
                }
            }
            log.info("onAuthenticationSuccess5-> {}",  accessToken);
            // 인증 관련 설정값, 쿠키 제거
            String targetUrl = getTargetUrl(accessToken);
            clearAuthenticationAttributes(request, response);
            // 리다이렉트
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        }

        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void saveRefreshToken(Long userId, String newRefreshToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByUserId(userId)
                .map(entity -> entity.update(newRefreshToken))
                .orElse(new RefreshToken(userId, newRefreshToken));

        refreshTokenRepository.save(refreshToken);
    }
    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        int cookieMaxAge = (int) REFRESH_TOKEN_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_COOKIE_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, cookieMaxAge);
    }

    // 인증 관련 설정값, 쿠키 제거
    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        assert authorizationRequestRepository != null;
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_PATH)
                .queryParam("token", token)
                .build()
                .toUriString();
    }
}
