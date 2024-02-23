package kroryi.spring.service;

import kroryi.spring.dto.MemberDto;
import kroryi.spring.entity.Member;
import kroryi.spring.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class TokenService {

    private final JwtUtil tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final MemberService userService;
    private final ModelMapper modelMapper;

    public String createNewAccessToken(String refreshToken){
        // 토큰 유효성 검사에 실패하면 예외 발생
        if(!tokenProvider.validateToken(refreshToken)){
            throw new IllegalArgumentException("unexpected token");
        }
        Long userId = refreshTokenService.findByRefreshToken(refreshToken).getUserId();
        Member member = userService.findByUserId(userId);
        return tokenProvider.createAccessToken(modelMapper.map(member, MemberDto.class));
    }
}