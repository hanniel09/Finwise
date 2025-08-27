package com.hanniel.finwise.controllers.user;

import com.hanniel.finwise.domains.users.UserProfilePatchRequest;
import com.hanniel.finwise.domains.users.UserProfileRequest;
import com.hanniel.finwise.domains.users.UserProfileResponse;
import com.hanniel.finwise.services.user.UserProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user-profile")
@RequiredArgsConstructor
public class UserProfileController {

    private final UserProfileService userProfileService;

    @PostMapping
    public ResponseEntity<UserProfileResponse> createProfile(@AuthenticationPrincipal(expression = "username") String email,
                                                             @Valid @RequestBody UserProfileRequest userProfileRequest) {
        UserProfileResponse userResponse = userProfileService.createProfileByEmail(email, userProfileRequest);
        return new ResponseEntity<UserProfileResponse>(userResponse, HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity<UserProfileResponse> getProfile(@AuthenticationPrincipal(expression = "username") String email){
        UserProfileResponse userProfile = userProfileService.getProfileByEmail(email);
        return ResponseEntity.ok(userProfile);
    }

    @PutMapping
    public ResponseEntity<UserProfileResponse> updateProfile(@AuthenticationPrincipal(expression = "username") String email,
                                             @Valid @RequestBody UserProfileRequest userProfileRequest) {
       UserProfileResponse userProfile = userProfileService.updateProfileByEmail(email, userProfileRequest);
       return ResponseEntity.ok(userProfile);
    }

    @PatchMapping
    public ResponseEntity<UserProfileResponse> patchProfile(@AuthenticationPrincipal(expression = "username") String email,
                                                            @Valid @RequestBody UserProfilePatchRequest userProfilePatchRequest) {
        UserProfileResponse userProfileResponse = userProfileService.patchProfileByEmail(email, userProfilePatchRequest);
        return ResponseEntity.ok(userProfileResponse);
    }

    @DeleteMapping
    public void deactivateProfile(@AuthenticationPrincipal(expression = "username") String email) {
        userProfileService.deactivateProfileByEmail(email);
    }

    @PostMapping("/reactivate")
    public UserProfileResponse reactivateProfile(@AuthenticationPrincipal(expression = "username")String email) {
        return userProfileService.reactivateProfileByEmail(email);
    }


}

