package ch.bbw.pr.tresorbackend.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.Value;

@Getter
@Setter
@Value
public class LoginUser {

    @NotEmpty(message="Email is required.")
    private String email;

    @NotEmpty(message="Password is required.")
    private String password;

}