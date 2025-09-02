package com.hanniel.finwise.controllers.user;

import com.hanniel.finwise.domains.users.UserProfilePatchRequest;
import com.hanniel.finwise.domains.users.UserProfileRequest;
import com.hanniel.finwise.domains.users.UserProfileResponse;
import com.hanniel.finwise.services.user.UserProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/admin/user-profile")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminUserProfileController {

    private final UserProfileService userProfileService;

    @GetMapping("/{userId}")
    public ResponseEntity<UserProfileResponse> getUserProfileById(@PathVariable UUID userId) {
        UserProfileResponse userProfile = userProfileService.getProfileByUserId(userId);
        return ResponseEntity.ok(userProfile);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<UserProfileResponse> updateUserProfileById(@PathVariable UUID userId, @Valid @RequestBody UserProfileRequest request) {
        UserProfileResponse userProfile = userProfileService.updateProfileById(userId, request);
        return ResponseEntity.ok(userProfile);
    }

    @PatchMapping("/{userId}")
    public ResponseEntity<UserProfileResponse> patchUserProfileById(@PathVariable UUID userId, @Valid @RequestBody UserProfilePatchRequest request) {
        UserProfileResponse userProfile = userProfileService.patchProfileById(userId, request);
        return ResponseEntity.ok(userProfile);
    }

    @DeleteMapping("/deactivate/{userId}")
    public void deactivateUserProfileById(@PathVariable UUID userId) {
        userProfileService.deactivateProfileById(userId);
    }

    @PostMapping("/{userId}")
    public ResponseEntity<UserProfileResponse> reactivateProfileById(@PathVariable UUID userId){
        UserProfileResponse userProfile = userProfileService.reactivateProfileById(userId);
        return ResponseEntity.ok(userProfile);
    }

    @DeleteMapping("/{userId}")
    public void deleteUserProfileById(@PathVariable UUID userId) {
        userProfileService.deleteProfile(userId);
    }
}
