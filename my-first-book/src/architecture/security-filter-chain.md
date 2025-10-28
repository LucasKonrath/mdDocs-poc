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