package by.itechart.cargo.controller;


import by.itechart.cargo.dto.authorization_dto.AuthorizationRequest;
import by.itechart.cargo.dto.authorization_dto.AuthorizationResponse;
import by.itechart.cargo.dto.authorization_dto.ResetPasswordMail;
import by.itechart.cargo.dto.authorization_dto.ResetPasswordRequest;
import by.itechart.cargo.dto.model_dto.user.UserSaveRequest;
import by.itechart.cargo.elasticsearch.ElasticsearchTestDataInserter;
import by.itechart.cargo.exception.AlreadyExistException;
import by.itechart.cargo.exception.IncorrectPasswordException;
import by.itechart.cargo.exception.NotFoundException;
import by.itechart.cargo.exception.ServiceException;
import by.itechart.cargo.service.AuthorizationService;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.Map;

@RestController
@RequestMapping("/v1/api/auth")
@Validated
public class AuthorizationController {

    @Value("${spring.security.oauth2.client.registration.github.client-id}")
    private String oauthGithubClientId;

    @Value("${spring.security.oauth2.client.registration.github.client-secret}")
    private String oauthGithubClientSecret;

    private final AuthorizationService authorizationService;
    private final ElasticsearchTestDataInserter testDataInserter;

    @Autowired
    public AuthorizationController(AuthorizationService authorizationService, ElasticsearchTestDataInserter testDataInserter) {
        this.authorizationService = authorizationService;
        this.testDataInserter = testDataInserter;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthorizationResponse> login(@RequestBody @Valid AuthorizationRequest authorizationRequest) throws NotFoundException {
//        testDataInserter.insertTestData();
        return ResponseEntity.ok(authorizationService.login(authorizationRequest));
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout() {
        authorizationService.logout();
        return ResponseEntity.ok("User has been logouted");
    }


    @PostMapping("/registration")
    public ResponseEntity<String> registration(@RequestBody @Valid UserSaveRequest request)
            throws AlreadyExistException, IncorrectPasswordException, NotFoundException {
        authorizationService.registration(request);
        return ResponseEntity.ok("Registration completed successfully");
    }

    @PostMapping("/mail")
    public ResponseEntity<String> resetPasswordMail(@RequestBody @Valid ResetPasswordMail request)
            throws NotFoundException, ServiceException, AlreadyExistException {
        authorizationService.resetPassword(request.getEmail());
        return ResponseEntity.ok("Instructions have been sent to email " + request.getEmail());
    }

    @PostMapping("/password")
    public ResponseEntity<String> resetPassword(@RequestBody @Valid ResetPasswordRequest request)
            throws NotFoundException, IncorrectPasswordException {
        authorizationService.resetPassword(request);
        return ResponseEntity.ok("Password has been change");
    }


    @GetMapping("/oauth2")
    public RedirectView authenticate(@RequestParam String code, RedirectAttributes redirectAttributes) throws NotFoundException {
        String accessToken = requestAccessToken(code);
        String email = requestEmailByAccessToken(accessToken);
        AuthorizationResponse authorizationResponse = authorizationService.oauthLogin(email);
        redirectAttributes.addAttribute("jwttoken", authorizationResponse.getToken());
        HttpHeaders headers = new HttpHeaders();
        return new RedirectView("http://localhost:3000/parse-token");
    }


    public String requestAccessToken(String authorizationCode) throws NotFoundException {
        String credentials = oauthGithubClientId + ":" + oauthGithubClientSecret;
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));
        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "Basic " + encodedCredentials);
        HttpEntity<String> request = new HttpEntity<String>(headers);

        String access_token_url = "https://github.com/login/oauth/access_token";
        access_token_url += "?code=" + authorizationCode;
        access_token_url += "&grant_type=authorization_code";

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Object> responseEntity = restTemplate.exchange(access_token_url, HttpMethod.POST, request, Object.class);
        Map<String, String> tokenResponse = (Map<String, String>) responseEntity.getBody();
        return tokenResponse.get("access_token");
    }

    public String requestEmailByAccessToken(String accessToken) {
        HttpHeaders headers = new HttpHeaders();

        headers.add("Authorization", "token " + accessToken);
        HttpEntity<String> request = new HttpEntity<>(headers);

        String access_token_url = "https://api.github.com/user/emails";

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Object> responseEntity = restTemplate.exchange(access_token_url, HttpMethod.GET, request, Object.class);
        ArrayList<Map<String, String>> emails = (ArrayList<Map<String, String>>) responseEntity.getBody();
        return emails.get(0).get("email");
    }
}
