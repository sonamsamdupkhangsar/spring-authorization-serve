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
@IdClass(ClientOrganizationId.class) //composite id class - clientId & userId fields
@Table(name = "`ClientOrganization`")
public class ClientOrganization {
    private static final Logger LOG = LoggerFactory.getLogger(ClientOrganization.class);
    @Id
    private String clientId;
    @Id
    private UUID organizationId;

    public ClientOrganization(String clientId, UUID organizationId) {
        this.clientId = clientId;
        this.organizationId = organizationId;
    }

    public ClientOrganization() {

    }
    public String getClientId() {
        return this.clientId;
    }

    public UUID getOrganizationId() {
        return this.organizationId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientOrganization that = (ClientOrganization) o;
        return Objects.equals(clientId, that.clientId) && Objects.equals(organizationId, that.organizationId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, organizationId);
    }

    @Override
    public String toString() {
        return "ClientOrganization{" +
                "clientId='" + clientId + '\'' +
                ", organizationId=" + organizationId +
                '}';
    }
}
