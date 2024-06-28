
package cl.harf.springboot.client.client.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

/**
 * Clase de configuración de seguridad para el cliente OAuth2.
 */
@Configuration
public class SecurityConfig {
    
    /**
     * Configura la cadena de filtros de seguridad para la aplicación.
     *
     * @param http El objeto HttpSecurity para configurar la seguridad de la aplicación.
     * @return Una instancia de SecurityFilterChain.
     * @throws Exception Si ocurre un error al configurar la seguridad.
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authHttp) -> authHttp
        // Permite el acceso a la ruta "/authorized" sin autenticación
        .requestMatchers(HttpMethod.GET, "/authorized").permitAll()
        // Requiere que las solicitudes GET a "/list" tengan los permisos "SCOPE_read" o "SCOPE_write"
        .requestMatchers(HttpMethod.GET, "/list").hasAnyAuthority("SCOPE_read", "SCOPE_write")
        // Requiere que las solicitudes POST a "/create" tengan el permiso "SCOPE_write"
        .requestMatchers(HttpMethod.POST, "/create").hasAuthority("SCOPE_write")
        // Requiere autenticación para cualquier otra solicitud
        .anyRequest().authenticated())
        // Deshabilita la protección CSRF
        .csrf(csrf -> csrf.disable())
        // Configura la política de creación de sesiones como STATELESS
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // Configura el inicio de sesión OAuth2 con una página de inicio de sesión personalizada
        .oauth2Login(login -> login.loginPage("/oauth2/authorization/client-app"))
        // Configura el cliente OAuth2 con la configuración predeterminada
        .oauth2Client(withDefaults())
        // Configura el servidor de recursos OAuth2 para aceptar tokens JWT
        .oauth2ResourceServer(resourceServer -> resourceServer.jwt(withDefaults()));
        
        return http.build();
    }
}

// package cl.harf.springboot.client.client.auth;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.http.HttpMethod;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.web.SecurityFilterChain;
// import static org.springframework.security.config.Customizer.withDefaults;

// @Configuration
// public class SecurityConfig {

//     @Bean
//     SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
//         http.authorizeHttpRequests((authHttp) -> authHttp
//         .requestMatchers(HttpMethod.GET, "/authorized").permitAll()
//         .requestMatchers(HttpMethod.GET, "/list").hasAnyAuthority("SCOPE_read", "SCOPE_write")
//         .requestMatchers(HttpMethod.POST, "/create").hasAuthority("SCOPE_write")
//         .anyRequest().authenticated())
//         .csrf(csrf->csrf.disable())
//         .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//         .oauth2Login(login->login.loginPage("/oauth2/authorization/client-app"))
//         .oauth2Client(withDefaults())
//         .oauth2ResourceServer(resourceServer ->resourceServer.jwt(withDefaults()));

//         return http.build();
//     }

// }
