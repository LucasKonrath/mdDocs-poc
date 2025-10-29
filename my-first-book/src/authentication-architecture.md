# Authentication Architecture

SecurityContextHolder - The SecurityContextHolder is where Spring Security stores the details of who is authenticated.

SecurityContext - is obtained from the SecurityContextHolder and contains the Authentication of the currently authenticated user.

Authentication - Can be the input to AuthenticationManager to provide the credentials a user has provided to authenticate or the current user from the SecurityContext.

GrantedAuthority - An authority that is granted to the principal on the Authentication (i.e. roles, scopes, etc.)

AuthenticationManager - the API that defines how Spring Security’s Filters perform authentication.

ProviderManager - the most common implementation of AuthenticationManager.

AuthenticationProvider - used by ProviderManager to perform a specific type of authentication.

Request Credentials with AuthenticationEntryPoint - used for requesting credentials from a client (i.e. redirecting to a log in page, sending a WWW-Authenticate response, etc.)

AbstractAuthenticationProcessingFilter - a base Filter used for authentication. This also gives a good idea of the high level flow of authentication and how pieces work together.