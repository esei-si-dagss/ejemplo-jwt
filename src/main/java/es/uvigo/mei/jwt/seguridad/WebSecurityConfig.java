package es.uvigo.mei.jwt.seguridad;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import es.uvigo.mei.jwt.seguridad.autenticacion.UserDetailsServiceImpl;
import es.uvigo.mei.jwt.seguridad.jwt.FiltroAutenticacionJWT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailsServiceImpl userDetailsService;

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// Passwordencoder a usar
		return new BCryptPasswordEncoder();
	}

	@Bean
	public FiltroAutenticacionJWT filtroAutenticacionJWT() {
		// Filtro de autenticación de peticiones basado en JWT
		return new FiltroAutenticacionJWT();
	}

	@Override
	public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
		// Configuración de autenticación
		// - configura autenticacion para usar un "UserDetailService" propio y el "passwordEncoder" anterior
		authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// Configuracion de autorizacion
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and() // desactiva uso de cookies
				.cors().and() // habilita CORS
				.csrf().disable() // deshabilita CSRF
				.authorizeRequests().antMatchers("/api/auth/**").permitAll() // Permite acceso total a /api/auth
				                    .antMatchers("/api/pruebas/**").permitAll() // Permite acceso total a /api/pruebas (despues sera
									                    						// limitado con @PreAuthorize)
 				                    .anyRequest().authenticated();

		http.addFilterBefore(filtroAutenticacionJWT(), UsernamePasswordAuthenticationFilter.class);
		// Establece filtros por los que pasan las peticiones (y su orden)
		// - filtroAutenticacionJWT: comprueba que petición incluye un token JWT, lo valida 
		//  y extrae info. de autenticacion de usuarios de la BD
		// - UsernamePasswordAuthenticationFilter: filtro general que procesa info. de
		// autenticacion de usuarios
	}
}
