package kroryi.spring.dto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequestDto {
    @Email(message = "Email 입력은 필수입니다.")
    private String email;
    @NotNull(message = "Password 입력은 필수 입니다.")
    private String password;
}
