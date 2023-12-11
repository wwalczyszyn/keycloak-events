package io.phasetwo.keycloak.events;

import com.github.xgp.util.BackOff;
import com.github.xgp.util.ExponentialBackOff;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.AdminEventRepresentation;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.util.JsonSerialization;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Collectors;

import static java.net.HttpURLConnection.HTTP_MULT_CHOICE;
import static java.net.HttpURLConnection.HTTP_OK;

@JBossLog
public class HttpSenderEventListenerProvider extends SenderEventListenerProvider {

  protected static final String TARGET_URI = "targetUri";
  protected static final String RETRY = "retry";
  protected static final String SHARED_SECRET = "sharedSecret";
  protected static final String HMAC_ALGORITHM = "hmacAlgorithm";
  protected static final String BACKOFF_INITIAL_INTERVAL = "backoffInitialInterval";
  protected static final String BACKOFF_MAX_ELAPSED_TIME = "backoffMaxElapsedTime";
  protected static final String BACKOFF_MAX_INTERVAL = "backoffMaxInterval";
  protected static final String BACKOFF_MULTIPLIER = "backoffMultiplier";
  protected static final String BACKOFF_RANDOMIZATION_FACTOR = "backoffRandomizationFactor";
  protected static final String EVENT_TYPES = "eventTypes";
  protected static final String ADMIN_EVENT_TYPES = "adminEventTypes";

  public HttpSenderEventListenerProvider(KeycloakSession session, ScheduledExecutorService exec) {
    super(session, exec);
  }

  @Override
  BackOff getBackOff() {
    boolean retry = getBooleanOr(config, RETRY, true);
    log.debugf("Retry is %b %s", retry, getOr(config, RETRY, "[empty]"));
    if (!retry) return BackOff.STOP_BACKOFF;
    else
      return new ExponentialBackOff.Builder()
          .setInitialIntervalMillis(getIntOr(config, BACKOFF_INITIAL_INTERVAL, 500))
          .setMaxElapsedTimeMillis(getIntOr(config, BACKOFF_MAX_ELAPSED_TIME, 900000))
          .setMaxIntervalMillis(getIntOr(config, BACKOFF_MAX_INTERVAL, 60000))
          .setMultiplier(getDoubleOr(config, BACKOFF_MULTIPLIER, 1.5))
          .setRandomizationFactor(getDoubleOr(config, BACKOFF_RANDOMIZATION_FACTOR, 0.5))
          .build();
  }

  String getTargetUri() {
    return config.get(TARGET_URI).toString();
  }

  Optional<String> getSharedSecret() {
    return Optional.ofNullable(config.get(SHARED_SECRET)).map(Object::toString);
  }

  Optional<String> getHmacAlgorithm() {
    return Optional.ofNullable(config.get(HMAC_ALGORITHM)).map(Object::toString);
  }

  Set<String> getEnabledUserEventTypes() {
    return Arrays.stream(config.get(EVENT_TYPES).toString().split(","))
        .map(String::trim).map(String::toUpperCase).collect(Collectors.toSet());
  }

  Set<String> getEnabledAdminEventTypes() {
    return Arrays.stream(config.get(ADMIN_EVENT_TYPES).toString().split(","))
        .map(String::trim).map(String::toUpperCase).collect(Collectors.toSet());
  }

  @Override
  void send(SenderTask task) throws SenderException, IOException {
    Object event = task.getEvent();
    String targetUri = getTargetUri();

    if (config.containsKey(EVENT_TYPES) && !config.get(EVENT_TYPES).equals("*") && event instanceof EventRepresentation) {
      EventRepresentation eventRepresentation = (EventRepresentation) event;

      Set<String> includedEventTypes = getEnabledUserEventTypes();

      if (!includedEventTypes.isEmpty() && !includedEventTypes.contains(eventRepresentation.getType())) {
        log.debugf("skipping sending to %s event of type %s", targetUri, eventRepresentation.getType());
        return; // skip
      }
    } else if (config.containsKey(ADMIN_EVENT_TYPES) && !config.get(ADMIN_EVENT_TYPES).equals("*") && event instanceof AdminEventRepresentation) {
      AdminEventRepresentation adminEventRepresentation = (AdminEventRepresentation) event;
      String eventType = adminEventRepresentation.getResourceType() + ":" + adminEventRepresentation.getOperationType();
      String widlcardOperationEventType = adminEventRepresentation.getResourceType() + ":*";
      String widlcardResourceEventType = "*:" + adminEventRepresentation.getOperationType();

      Set<String> includedResourceTypes = getEnabledAdminEventTypes();

      if (!includedResourceTypes.isEmpty() && !includedResourceTypes.contains(eventType) && !includedResourceTypes.contains(widlcardOperationEventType) && !includedResourceTypes.contains(widlcardResourceEventType)) {
        log.debugf("skipping sending to %s admin event for event type %s", targetUri, eventType);
        return;
      }
    }
    send(task, targetUri, getSharedSecret(), getHmacAlgorithm());
  }

  protected void send(
      SenderTask task, String targetUri, Optional<String> sharedSecret, Optional<String> algorithm)
      throws SenderException, IOException {
    log.debugf("attempting send to %s", targetUri);
    try (CloseableHttpClient http = HttpClients.createDefault()) {
      //      SimpleHttp request = SimpleHttp.doPost(targetUri, session).json(task.getEvent());
      SimpleHttp request = SimpleHttp.doPost(targetUri, http).json(task.getEvent());
      sharedSecret.ifPresent(
          secret ->
              request.header(
                  "X-Keycloak-Signature",
                  hmacFor(task.getEvent(), secret, algorithm.orElse(HMAC_SHA256_ALGORITHM))));
      SimpleHttp.Response response = request.asResponse();
      int status = response.getStatus();
      log.debugf("sent to %s (%d)", targetUri, status);
      if (status < HTTP_OK || status >= HTTP_MULT_CHOICE) { // any 2xx is acceptable
        log.warnf("Sending failure (Server response:%d)", status);
        throw new SenderException(true);
      }
    } catch (SenderException se) {
      // rethrow existing SenderException
      throw se;
    } catch (Exception e) {
      log.warnf(e, "Sending exception to %s", targetUri);
      throw new SenderException(false, e);
    }
  }

  protected String hmacFor(Object o, String sharedSecret, String algorithm) {
    try {
      String data = JsonSerialization.writeValueAsString(o);
      return calculateHmacSha(data, sharedSecret, algorithm);
    } catch (Exception e) {
      log.warn("Unable to sign data", e);
    }
    return "";
  }

  private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
  private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

  public static String calculateHmacSha(String data, String key, String algorithm)
      throws SignatureException {
    String result = null;
    try {
      SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), algorithm);
      Mac mac = Mac.getInstance(algorithm);
      mac.init(signingKey);
      byte[] digest = mac.doFinal(data.getBytes());
      StringBuilder sb = new StringBuilder(digest.length * 2);
      String s;
      for (byte b : digest) {
        s = Integer.toHexString(0xFF & b);
        if (s.length() == 1) {
          sb.append('0');
        }
        sb.append(s);
      }
      result = sb.toString();
    } catch (Exception e) {
      throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
    }
    return result;
  }
}
