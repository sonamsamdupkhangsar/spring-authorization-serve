package me.sonam.auth;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * This will test the forgotUsernameController.
 */
@EnableAutoConfiguration
@ExtendWith(SpringExtension.class)
@SpringBootTest( webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ForgotUsernamePasswordIntegTest {
    private static final Logger LOG = LoggerFactory.getLogger(ForgotUsernamePasswordIntegTest.class);

    @Autowired
    private MockMvc mockMvc;
    private static MockWebServer mockWebServer;

    @BeforeAll
    static void setupMockWebServer() throws IOException {
        LOG.info("starting mock web server");
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        LOG.info("host: {}, port: {}", mockWebServer.getHostName(), mockWebServer.getPort());
    }

    @AfterAll
    public static void shutdownMockWebServer() throws IOException {
        LOG.info("shutdown and close mockWebServer");
        mockWebServer.shutdown();
        mockWebServer.close();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws IOException {
        LOG.info("mock the port for account-rest-service");
        r.add("account-rest-service.root", () -> "http://localhost:"+mockWebServer.getPort());
    }

    @Test
    public void forgotUsername() throws Exception {
        LOG.info("call forgotUsername endpoint");

        LOG.info("assert that the page returned is Email username help");
        this.mockMvc.perform(get("/forgotUsername")).andDo(print()).andExpect(status().isOk())
                .andExpect(content().string(containsString("Email username help")));
    }

    @Test
    public void forgotPassword() throws Exception {
        LOG.info("call forgotPassword endpoint");

        LOG.info("assert that the page returned is Change password help");
        this.mockMvc.perform(get("/forgotPassword")).andDo(print()).andExpect(status().isOk());
    }

    @Test
    public void emailUsername() throws Exception {
        LOG.info("email username");

        LOG.info("add mock response for email username call into queue");
        final String emailMsg = " {\"message\":\"email successfully sent\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(201).setBody(emailMsg));//"Account created successfully.  Check email for activating account"));

        this.mockMvc.perform(post("/forgotUsername")
                        .param("emailAddress", "dummy@xyqkl.com"))
                .andDo(print()).andExpect(status().isOk());
               // .andExpect(content().string(containsString("Your username has been sent to your email address.")));

        LOG.info("serve the queued mock response for email username http callout");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("PUT");
        assertThat(request.getPath()).startsWith("/accounts/email/dummy@xyqkl.com/authentication-id");
    }

    @Test
    public void emailMySecretForPasswordChange() throws Exception {
        LOG.info("email username");

        LOG.info("add mock response for email username call into queue");
        final String emailMsg = " {\"message\":\"email successfully sent\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json")
                .setResponseCode(201).setBody(emailMsg));//"Account created successfully.  Check email for activating account"));

        this.mockMvc.perform(post("/forgotPassword")
                        .param("email", "sonam@sonam.com"))

                .andDo(print()).andExpect(status().isOk());
                //.andExpect(content().string(containsString("Check your email for changing your password.")));

        LOG.info("serve the queued mock response for email username http callout");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("PUT");
        assertThat(request.getPath()).startsWith("/accounts/email/");
    }

    @Test
    public void emailMySecretForPasswordChangeThrowException() throws Exception {
        LOG.info("email username");

        LOG.info("add mock response for email username call into queue");
        final String emailMsg = " {\"error\":\"Account is not active or does not exist\"}";
        mockWebServer.enqueue(new MockResponse().setHeader("Content-Type", "application/json").setResponseCode(400).setBody(emailMsg));//"Account created successfully.  Check email for activating account"));

        this.mockMvc.perform(post("/forgotPassword")
                        .param("email", "sonam@sonam.com"))
                .andDo(print()).andExpect(status().isOk());
                //.andExpect(content().string(containsString("Account is not active or does not exist")));

        LOG.info("serve the queued mock response for email username http callout");
        RecordedRequest request = mockWebServer.takeRequest();
        assertThat(request.getMethod()).isEqualTo("PUT");
        assertThat(request.getPath()).startsWith("/accounts/email/");
    }
}