# Authentication Architecture

![alt text](image-1.png)

### AbstractAuthenticationProcessingFilter 

Base Filter used for authentication. This also gives a good idea of the high level flow of authentication and how pieces work together.

### Authentication 

Can be the input to AuthenticationManager to provide the credentials a user has provided to authenticate or the current user from the SecurityContext.


### AuthenticationManager 

The API that defines how Spring Security’s Filters perform authentication.

### ProviderManager 

The most common implementation of AuthenticationManager.

### AuthenticationProvider 

Used by ProviderManager to perform a specific type of authentication.

### SecurityContextHolder

The SecurityContextHolder is where Spring Security stores the details of who is authenticated.

![alt text](image.png)

```java
SecurityContext context = SecurityContextHolder.createEmptyContext(); 
Authentication authentication =
    new TestingAuthenticationToken("username", "password", "ROLE_USER"); 
context.setAuthentication(authentication);

SecurityContextHolder.setContext(context); 
```

### SecurityContext 

Is obtained from the SecurityContextHolder and contains the Authentication of the currently authenticated user.



### SessionAuthenticationStrategy

Executed when a user successfully authenticates to perform session-related activities. Handles session fixation protection, concurrent session control, and session registry updates.


### RememberMeServices

Generates and validates remember-me tokens that can persist authentication beyond the current session.

### AuthenticationFailureHandler

Called when authentication fails. Determines what to do upon auth fail, like redirecting, or returning error with specific JSON payload.

### AuthenticationSuccessHandler

Called when authentication succeeds. Determines what should happen after successful auth, like returning JWT token, redirecting to a specific page.

### ApplicationEventPublisher

Publishes application events that can be listened to by other parts of the application. Commonly used in Spring framework.

