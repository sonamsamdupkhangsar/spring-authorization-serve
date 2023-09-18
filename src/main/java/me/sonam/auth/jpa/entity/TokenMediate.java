package me.sonam.auth.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import me.sonam.auth.jpa.repo.TokenMediateRepository;

@Entity
@Table(name = "`TokenMediate`")
public class TokenMediate {
    @Id
    private String clientId;

    public TokenMediate() {}
    public TokenMediate(String clientId) {
        this.clientId = clientId;
    }
    public String getClientId() {
        return this.clientId;
    }


}
