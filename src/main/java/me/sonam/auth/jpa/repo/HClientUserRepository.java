package me.sonam.auth.jpa.repo;

import me.sonam.auth.jpa.entity.ClientUser;
import me.sonam.auth.jpa.entity.ClientUserId;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface HClientUserRepository extends JpaRepository<ClientUser, ClientUserId> {

    List<ClientUser> findByUserId(UUID userId);
    List<ClientUser> findByClientId(UUID clientId);
    Optional<ClientUser> findByClientIdAndUserId(UUID clientId, UUID userId);
    Optional<Boolean> existsByClientIdAndUserId(UUID clientId, UUID userId);
    long deleteByClientId(UUID clientId);
    boolean existsByClientId(UUID clientId);
}
