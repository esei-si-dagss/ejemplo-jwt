package es.uvigo.mei.jwt.controllers.dtos;

import java.util.List;

public class RespuestaJWT {
	private String token;
	private Long id;
	private String login;
	private List<String> roles;

	public RespuestaJWT() {
		super();
	}

	public RespuestaJWT(String token, Long id, String login, List<String> roles) {
		super();
		this.token = token;
		this.id = id;
		this.login = login;
		this.roles = roles;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getLogin() {
		return login;
	}

	public void setLogin(String login) {
		this.login = login;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}

}
