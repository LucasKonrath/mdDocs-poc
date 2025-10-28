# Filter Chain

![alt text](image-1.png)

- Filter chain is a sequence of filters
- Each call can either continue the chain or break it
- Ordering matters a lot in the filter chains, as we'll see later

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(Customizer.withDefaults())
            .httpBasic(Customizer.withDefaults())
            .formLogin(Customizer.withDefaults())
            .authorizeHttpRequests(authorize -> 
                authorize.anyRequest().authenticated());
        return http.build();
    }
}
```

## Adding filters to the chain
| Filter Type | Place after | Already happened |
| :----       | :---------  | :--------------- |
| Exploit Protection | SecurityContextHolderFilter | Security context loaded |
| Authentication Filter | LogoutFilter | Exploit protection |
| Authorization Filter | AnonymousAuthenticationFilter | Authenticated |

## Defining Filter Chain beans

```java
// Chain 1: JWT - Stateless
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/api/public/**").permitAll()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            .httpBasic(basic -> basic.disable())
            .formLogin(form -> form.disable());
        return http.build();
    }

    // Chain 2: stateful basic auth
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/**", "/public/**").permitAll()
                    .anyRequest().authenticated()
            )
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }
```