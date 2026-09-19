package online.cyclothone.bounty;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public final class PayoutWorker {
    private static final Logger log = LoggerFactory.getLogger(PayoutWorker.class);
    private final HttpClient http;
    private final String apiUrl;
    private final String internalKey;
    private final int batch;

    public PayoutWorker(
        @Value("\${cyclothone.bounty.api}") String apiUrl,
        @Value("\${cyclothone.bounty.internal-key}") String internalKey,
        @Value("\${cyclothone.bounty.batch:50}") int batch
    ) {
        if (apiUrl == null || apiUrl.isBlank() || internalKey == null || internalKey.isBlank()) {
            throw new IllegalArgumentException("bounty worker requires API URL and internal key");
        }
        if (batch < 1 || batch > 200) throw new IllegalArgumentException("batch must be 1..200");
        this.apiUrl = apiUrl.replaceAll("/+$", "");
        this.internalKey = internalKey;
        this.batch = batch;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    @Scheduled(fixedDelayString="\${cyclothone.bounty.poll-ms:300000}")
    public void process() {
        try {
            var request = HttpRequest.newBuilder()
                .uri(URI.create(apiUrl + "/v1/bounty/payouts/run"))
                .timeout(Duration.ofSeconds(15))
                .header("Authorization", "Bearer " + internalKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"batch\":" + batch + "}"))
                .build();
            var response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                log.warn("bounty payout claim returned HTTP {}", response.statusCode());
                return;
            }
            log.info("bounty payout claim completed: {}", response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("bounty payout worker interrupted");
        } catch (Exception e) {
            log.warn("bounty payout claim failed", e);
        }
    }
}
