package es.uvigo.mei.jwt.daos;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;


import es.uvigo.mei.jwt.entidades.Usuario;

public interface UsuarioDAO extends JpaRepository<Usuario, Long>{
	  public Optional<Usuario> findByLogin(String login);
	  public Boolean existsByLogin(String login);
	  public Boolean existsByEmail(String email);
}
