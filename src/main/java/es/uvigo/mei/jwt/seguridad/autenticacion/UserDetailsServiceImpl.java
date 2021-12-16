package es.uvigo.mei.jwt.seguridad.autenticacion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import es.uvigo.mei.jwt.daos.UsuarioDAO;
import es.uvigo.mei.jwt.entidades.Usuario;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
  @Autowired
  UsuarioDAO usuarioDAO;

  @Override
  @Transactional
  public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
    Usuario usuario = usuarioDAO.findByLogin(login)
        .orElseThrow(() -> new UsernameNotFoundException("No se encuentra un usuario con el login " + login));

    return new UserDetailsImpl(usuario);
  }

}
