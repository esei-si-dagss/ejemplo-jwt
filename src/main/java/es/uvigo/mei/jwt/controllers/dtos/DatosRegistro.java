package es.uvigo.mei.jwt.controllers.dtos;

import java.io.Serializable;
import java.util.Set;

public class DatosRegistro implements Serializable {
	private String login;
	private String password;
	private String nombre;
	private String email;
	private Set<String> roles;
	
	public DatosRegistro() {		
	}

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getNombre() {
		return nombre;
	}

	public void setNombre(String nombre) {
		this.nombre = nombre;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public Set<String> getRoles() {
		return roles;
	}

	public void setRoles(Set<String> roles) {
		this.roles = roles;
	}
	
	
}
