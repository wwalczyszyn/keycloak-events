package io.phasetwo.keycloak.resources;

import static io.phasetwo.keycloak.Helpers.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.github.xgp.http.server.Server;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.phasetwo.keycloak.events.HttpSenderEventListenerProvider;
import io.phasetwo.keycloak.representation.WebhookRepresentation;
import java.io.File;
import java.net.URLEncoder;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import lombok.extern.jbosslog.JBossLog;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@JBossLog
@Testcontainers
public class WebhooksResourceTest {
  static final List<File> dependencies = Maven.resolver()
                                         .loadPomFromFile("./pom.xml")
                                         .resolve("org.keycloak:keycloak-admin-client")
                                         .withoutTransitivity().asList(File.class);

  @Container static final KeycloakContainer server = new KeycloakContainer("quay.io/keycloak/keycloak:20.0.1").withContextPath("/auth/").withProviderClassesFrom("target/classes").withProviderLibsFrom(dependencies);

  CloseableHttpClient httpClient = HttpClients.createDefault();

  String baseUrl() {
    return server.getAuthServerUrl() + "/realms/master/webhooks";
  }

  String urlencode(String u) {
    try {
      return URLEncoder.encode(u, "UTF-8");
    } catch (Exception e) {
      return "";
    }
  }
  
  Keycloak getKeycloak() {
    assertTrue(server.isRunning());
    return server.getKeycloakAdminClient();
  }

  @Test
  public void testAddGetWebhook() throws Exception {
    Keycloak keycloak = getKeycloak();

    String url = "https://example.com/testAddGetWebhook";
    String id = createWebhook(keycloak, httpClient, baseUrl(), url, "A3jt6D8lz", null);

    SimpleHttp.Response response =
        SimpleHttp.doGet(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(200));
    WebhookRepresentation rep = response.asJson(new TypeReference<WebhookRepresentation>() {});
    assertNotNull(rep);
    assertTrue(rep.isEnabled());
    assertNotNull(rep.getId());
    assertNotNull(rep.getCreatedAt());
    assertNotNull(rep.getCreatedBy());
    assertThat(rep.getRealm(), is("master"));
    assertThat(rep.getUrl(), is(url));
    assertNull(rep.getSecret());

    response =
        SimpleHttp.doDelete(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(204));
  }

  @Test
  public void testUpdateGetWebhook() throws Exception {
    Keycloak keycloak = getKeycloak();

    String url = "https://example.com/testUpdateGetWebhook";
    String secret = "A3jt6D8lz";
    String id = createWebhook(keycloak, httpClient, baseUrl(), url, secret, null);

    WebhookRepresentation rep = new WebhookRepresentation();
    rep.setUrl(url + "/disabled");
    rep.setEnabled(false);
    rep.setSecret(secret);
    rep.setEventTypes(ImmutableSet.of("*"));

    SimpleHttp.Response response =
        SimpleHttp.doPut(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .json(rep)
            .asResponse();
    assertThat(response.getStatus(), is(204));

    response =
        SimpleHttp.doGet(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(200));
    rep = response.asJson(new TypeReference<WebhookRepresentation>() {});
    assertNotNull(rep);
    assertFalse(rep.isEnabled());
    assertNotNull(rep.getId());
    assertNotNull(rep.getCreatedAt());
    assertNotNull(rep.getCreatedBy());
    assertThat(rep.getRealm(), is("master"));
    assertThat(rep.getUrl(), is(url + "/disabled"));
    assertNull(rep.getSecret());

    response =
        SimpleHttp.doDelete(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(204));
  }

  @Test
  public void testRemoveWebhoook() throws Exception {
    Keycloak keycloak = getKeycloak();

    String id =
        createWebhook(
            keycloak,
            httpClient,
            baseUrl(),
            "https://en6fowyrouz6q4o.m.pipedream.net",
            "A3jt6D8lz",
            null);

    SimpleHttp.Response response =
        SimpleHttp.doDelete(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(204));

    response =
        SimpleHttp.doGet(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(404));
  }

  @Test
  public void testWebhookReceivesEvent() throws Exception {
    Keycloak keycloak = getKeycloak();
    // update a realm with the ext-event-webhook listener
    addEventListener(keycloak, "master", "ext-event-webhook");

    AtomicReference<String> body = new AtomicReference<String>();
    AtomicReference<String> shaHeader = new AtomicReference<String>();
    // create a server on a free port with a handler to listen for the event
    int port = nextFreePort(8083, 10000);
    String id =
        createWebhook(
            keycloak,
            httpClient,
            baseUrl(),
            "http://127.0.0.1:" + port + "/webhook",
            "qlfwemke",
            ImmutableSet.of("admin.*"));

    Server server = new Server(port);
    server
        .router()
        .POST(
            "/webhook",
            (request, response) -> {
              String r = request.body();
              log.infof("body %s", r);
              body.set(r);
              shaHeader.set(request.header("X-Keycloak-Signature"));
              response.body("OK");
              response.status(202);
            });
    server.start();
    Thread.sleep(1000l);

    // cause an event to be sent
    createUser(keycloak, "master", "abc123");

    Thread.sleep(1000l);

    // check the handler for the event, after a delay
    assertNotNull(body.get());
    assertThat(body.get(), containsString("abc123"));
    // check hmac
    String sha =
        HttpSenderEventListenerProvider.calculateHmacSha(body.get(), "qlfwemke", "HmacSHA256");
    log.infof("hmac header %s sha %s", shaHeader.get(), sha);
    assertThat(shaHeader.get(), is(sha));

    server.stop();

    SimpleHttp.Response response =
        SimpleHttp.doDelete(baseUrl() + "/" + urlencode(id), httpClient)
            .auth(keycloak.tokenManager().getAccessTokenString())
            .asResponse();
    assertThat(response.getStatus(), is(204));
  }
}
