package io.github.quizmeup.authorization.server.feign;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient("user-application")
public interface UserFeignClient {

    @GetMapping("/api/v1/users-by-email/{email}")
    UserResponse findUserByEmail(@PathVariable("email") String email);

    @PostMapping("/api/v1/users")
    MessageResponse createUser(UserCreationRequest userCreationRequest);

    record UserResponse(String email, String password) {
    }

    record UserCreationRequest(@Email String email, @NotBlank String password) {
    }

    record MessageResponse(String message) {
    }
}
