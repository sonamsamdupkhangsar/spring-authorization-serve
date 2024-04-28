package me.sonam.auth.jpa.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.Objects;
import java.util.UUID;

@Entity
@IdClass(ClientUserId.class) //composite id class - clientId & userId fields
@Table(name = "`ClientUser`")
public class ClientUser {
    private static final Logger LOG = LoggerFactory.getLogger(ClientUser.class);
    @Id
    private UUID clientId; //this is the client.id field, not Client.clientId
    @Id
    private UUID userId;

    public ClientUser(UUID clientId, UUID userId) {
        this.clientId = clientId;
        this.userId = userId;
    }

    public ClientUser() {

    }
    public UUID getClientId() {
        return this.clientId;
    }

    public UUID getUserId() {
        return this.userId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientUser that = (ClientUser) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, userId);
    }

    @Override
    public String toString() {
        return "ClientUser{" +
                "clientId='" + clientId + '\'' +
                ", userId=" + userId +
                '}';
    }
}
