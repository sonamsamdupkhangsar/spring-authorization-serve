package me.sonam.auth.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/health")
public class LivenessReadinessRestService {
    private static final Logger LOG = LoggerFactory.getLogger(LivenessReadinessRestService.class);

    @GetMapping("/liveness")
    @ResponseStatus(HttpStatus.OK)
    public String liveness() {
        LOG.debug("alive");
        return "live";
    }

    @GetMapping("/readiness")
    public String readiness() {
        LOG.debug("ready");
        return "ready";
    }
}
