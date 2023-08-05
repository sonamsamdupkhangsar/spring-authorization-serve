package me.sonam.auth.jpa.repo;

import me.sonam.auth.jpa.entity.TokenMediate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TokenMediateRepository extends JpaRepository<TokenMediate, String> {
}
