package me.sonam.auth;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CharacterAtIndexTest {
    private static final Logger LOG = LoggerFactory.getLogger(CharacterAtIndexTest.class);

    @Test
    public void atIndex() {
        final String string = "https://api-gateway.sonam.cloud/issuer/oauth2/authorize?response_type=code&client_id=nextjs-client&redirect_uri=https://nextauth.sonam.cloud/api/auth/callback/myauth&state=0vU4103nxGSRekKQ6G_FF_Qy8kLk6kxVauPMCm_qGNE&scope=openid email profile";
        int index = 228;

        LOG.info("character at index {} is `{}`, -1 is {}", index, string.charAt(index), string.charAt(index-1));
        LOG.info("character at index {} is `{}`, -1 is {}", index, string.charAt(index), string.charAt(index-1));
    }


}
