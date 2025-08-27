package com.hanniel.finwise.services.user;

import com.hanniel.finwise.domains.auth.UserCredentials;
import com.hanniel.finwise.domains.users.UserProfile;
import com.hanniel.finwise.domains.users.UserProfilePatchRequest;
import com.hanniel.finwise.domains.users.UserProfileRequest;
import com.hanniel.finwise.domains.users.UserProfileResponse;
import com.hanniel.finwise.repositories.auth.UserCredentialsRepository;
import com.hanniel.finwise.repositories.users.UserProfileRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserProfileService {

    private final UserProfileRepository userProfileRepository;
    private final UserCredentialsRepository userCredentialsRepository;

    @Transactional
    public UserProfileResponse createProfileByEmail(String email, UserProfileRequest request) {
        UserCredentials credentials = userCredentialsRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("Credentials not found"));

        if(userProfileRepository.findByCredentialsId(credentials.getId()).isPresent()){
            throw  new IllegalStateException("Profile already exists");
        }

        UserProfile userProfile = new UserProfile();

        userProfile.setCredentials(credentials);
        credentials.setProfile(userProfile);


        userProfile.setName(request.name());
        userProfile.setLastName(request.lastName());
        userProfile.setAge(request.age());
        userProfile.setOccupation(request.occupation());
        userProfile.setSalary(request.salary());
        userProfile.setFixedIncome(request.fixedIncome());
        userProfile.setMonthlyBudget(request.monthlyBudget());
        userProfile.setDefaultCurrency(request.defaultCurrency());
        userProfile.setRiskProfile(request.riskProfile());

        userProfileRepository.save(userProfile);

        return toResponse(userProfile);
    }

    @Transactional(readOnly = true)
    public UserProfileResponse getProfileByUserId(UUID userId){
        return userProfileRepository.findByCredentialsId(userId)
                .map(this::toResponse)
                .orElseThrow(() -> new EntityNotFoundException("User profile not found for ID: " + userId));

    }

    @Transactional(readOnly = true)
    public UserProfileResponse getProfileByEmail(String email) {
        UserCredentials credentials = userCredentialsRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("Credentials not found for email: " + email));
        return userProfileRepository.findByCredentialsId(credentials.getId())
                .map(this::toResponse)
                .orElseThrow(() -> new EntityNotFoundException("Profile not found for email: " + email));
    }

    public UserProfileResponse updateProfileByEmail(String email, UserProfileRequest request) {
        UserCredentials credentials = findCredentialsByEmail(email);
        return updateProfileByCredentialsId(credentials.getId(), request);
    }

    public UserProfileResponse updateProfileById(UUID userId, UserProfileRequest request) {
        return updateProfileByCredentialsId(userId, request);
    }

    private UserProfileResponse updateProfileByCredentialsId(UUID credentialsId, UserProfileRequest updateData){

        UserProfile existingUser = userProfileRepository.findByCredentialsId(credentialsId)
                .orElseThrow(() -> new EntityNotFoundException("Profile not found"));

        existingUser.setName(updateData.name());
        existingUser.setLastName(updateData.lastName());
        existingUser.setAge(updateData.age());
        existingUser.setOccupation(updateData.occupation());
        existingUser.setSalary(updateData.salary());
        existingUser.setFixedIncome(updateData.fixedIncome());
        existingUser.setMonthlyBudget(updateData.monthlyBudget());
        existingUser.setDefaultCurrency(updateData.defaultCurrency());
        existingUser.setRiskProfile(updateData.riskProfile());

        return toResponse(userProfileRepository.save(existingUser));
    }

    public UserProfileResponse patchProfileByEmail(String email, UserProfilePatchRequest request) {
        UserCredentials credentials = findCredentialsByEmail(email);
        return patchProfileByCredentialsId(credentials.getId(), request);
    }

    public UserProfileResponse patchProfileById(UUID userId, UserProfilePatchRequest request) {
        return patchProfileByCredentialsId(userId, request);
    }

    private UserProfileResponse patchProfileByCredentialsId(UUID userId, UserProfilePatchRequest patch){
        UserProfile existingUser = userProfileRepository.findByCredentialsId(userId)
                .orElseThrow(() -> new EntityNotFoundException("User profile not found for ID: " + userId));

        if(patch.name() != null) existingUser.setName(patch.name());
        if(patch.lastName() != null) existingUser.setLastName(patch.lastName());
        if(patch.age() != null) {
            if (patch.age() < 13) throw new IllegalArgumentException("Age must be greater than 12");
            existingUser.setAge(patch.age());
        }
        if(patch.occupation() != null) existingUser.setOccupation(patch.occupation());
        if(patch.salary() != null) existingUser.setSalary(patch.salary());
        if(patch.fixedIncome() != null) existingUser.setFixedIncome(patch.fixedIncome());
        if(patch.monthlyBudget() != null) existingUser.setMonthlyBudget(patch.monthlyBudget());
        if(patch.defaultCurrency() != null) existingUser.setDefaultCurrency(patch.defaultCurrency());
        if(patch.riskProfile() != null) existingUser.setRiskProfile(patch.riskProfile());

        return toResponse(userProfileRepository.save(existingUser));
    }

    public void deactivateProfileByEmail(String email) {
        UserCredentials credentials = findCredentialsByEmail(email);
        deactivateProfileByCredentialsId(credentials.getId());
    }

    public UserProfileResponse deactivateProfileById(UUID userId){
        return deactivateProfileByCredentialsId(userId);
    }

    private UserProfileResponse deactivateProfileByCredentialsId(UUID userId){
        UserProfile existingUser = userProfileRepository.findByCredentialsId(userId)
                .orElseThrow(() -> new EntityNotFoundException("Profile not found"));
        existingUser.setAccountActive(false);
        existingUser.setDeactivatedAt(LocalDateTime.now());

        return toResponse(userProfileRepository.save(existingUser));
    }

    public UserProfileResponse reactivateProfileByEmail(String email) {
        UserCredentials credentials = findCredentialsByEmail(email);
        return reactivateProfileByCredentialsId(credentials.getId());
    }

    public UserProfileResponse reactivateProfileById(UUID userId){
        return reactivateProfileByCredentialsId(userId);
    }


    private UserProfileResponse reactivateProfileByCredentialsId(UUID userId) {
        UserProfile existingUser = userProfileRepository.findByCredentialsId(userId)
                .orElseThrow(() -> new EntityNotFoundException("Profile not found"));

        existingUser.setAccountActive(true);
        existingUser.setDeactivatedAt(null);

        return toResponse(userProfileRepository.save(existingUser));
    }


    @Transactional
    public void deleteProfile(UUID userId){
        UserProfile existingUser = userProfileRepository.findByCredentialsId(userId)
                .orElseThrow(() -> new EntityNotFoundException("User profile not found for ID: " + userId));

        userProfileRepository.delete(existingUser);
    }

    private UserCredentials findCredentialsByEmail(String email) {
        return userCredentialsRepository.findByEmail(email)
                .orElseThrow(() -> new EntityNotFoundException("Credentials not found for email: " + email));
    }

    private UserCredentials findCredentialsById(UUID id){
        return userCredentialsRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Credentials not found for id: " + id));
    }

    private UserProfileResponse findResponseByCredentialsId(UUID id) {
        return userProfileRepository.findByCredentialsId(id)
                .map(this::toResponse)
                .orElseThrow(() -> new EntityNotFoundException("Profile not found"));
    }


    private UserProfileResponse toResponse(UserProfile profile) {
        return new UserProfileResponse(
                profile.getUuid(),
                profile.getName(),
                profile.getLastName(),
                profile.getAge(),
                profile.getOccupation(),
                profile.getSalary(),
                profile.getFixedIncome(),
                profile.getMonthlyBudget(),
                profile.getDefaultCurrency(),
                profile.getRiskProfile(),
                profile.getCreatedAt(),
                profile.getUpdatedAt(),
                profile.isAccountActive()
                );
    }

}
