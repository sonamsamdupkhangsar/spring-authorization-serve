package me.sonam.auth.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import me.sonam.auth.jpa.repo.TokenMediateRepository;

import java.util.UUID;

@Entity
@Table(name = "`TokenMediate`")
public class TokenMediate {

    /**
     * clientId is the {@link Client#getId()} field
     */
    @Id
    private UUID clientId;

    public TokenMediate() {}
    public TokenMediate(UUID clientId) {
        this.clientId = clientId;
    }
    public UUID getClientId() {
        return this.clientId;
    }


}
