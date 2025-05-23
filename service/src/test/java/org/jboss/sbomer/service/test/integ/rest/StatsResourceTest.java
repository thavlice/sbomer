/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.sbomer.service.test.integ.rest;

import java.util.Map;

import org.hamcrest.CoreMatchers;
import org.jboss.sbomer.service.feature.sbom.service.SbomService;
import org.jboss.sbomer.service.test.integ.rest.StatsResourceTest.CustomConfig;
import org.jboss.sbomer.service.test.utils.umb.TestUmbProfile;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.mockito.InjectSpy;
import io.restassured.RestAssured;

@QuarkusTest
@TestProfile(CustomConfig.class)
class StatsResourceTest {
    public static class CustomConfig extends TestUmbProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "sbomer.release",
                    "sbomer-abc",
                    "app.env",
                    "prod",
                    "hostname",
                    "localhost",
                    "sbomer.deployment.target",
                    "aws",
                    "sbomer.deployment.type",
                    "preprod",
                    "sbomer.deployment.zone",
                    "us-east-1",
                    "sbomer.features.umb.enabled",
                    "false");
        }

    }

    @InjectSpy
    SbomService sbomService;

    @Nested
    class V1Alpha3 {

        final String apiVersion = "v1alpha3";

        @Test
        void testEmptyStatsEndpoint() {
            RestAssured.given()
                    .when()
                    .get(String.format("/api/%s/stats", apiVersion))
                    .then()
                    .statusCode(200)
                    .body("resources.sboms.total", CoreMatchers.is(2))
                    .body("resources.generationRequests.total", CoreMatchers.is(2))
                    .body("resources.generationRequests.inProgress", CoreMatchers.is(0))
                    .body("uptime", CoreMatchers.isA(String.class))
                    .body("uptimeMillis", CoreMatchers.isA(Integer.class))
                    .body("version", CoreMatchers.isA(String.class))
                    .body("appEnv", CoreMatchers.is("prod"))
                    .body("hostname", CoreMatchers.is("localhost"))
                    .body("deployment.target", CoreMatchers.is("aws"))
                    .body("deployment.type", CoreMatchers.is("preprod"))
                    .body("deployment.zone", CoreMatchers.is("us-east-1"))
                    .body("release", CoreMatchers.is("sbomer-abc"));
        }

        @Test
        void testStatsEndpoint() {
            Mockito.when(sbomService.countSboms()).thenReturn(12L);
            Mockito.when(sbomService.countSbomGenerationRequests()).thenReturn(500L);

            RestAssured.given()
                    .when()
                    .get(String.format("/api/%s/stats", apiVersion))
                    .then()
                    .statusCode(200)
                    .body("resources.sboms.total", CoreMatchers.is(12))
                    .body("resources.generationRequests.total", CoreMatchers.is(500));
        }
    }

    @Nested
    class V1Beta1 {

        final String apiVersion = "v1beta1";

        @Test
        void testEmptyStatsEndpoint() {
            RestAssured.given()
                    .when()
                    .get(String.format("/api/%s/stats", apiVersion))
                    .then()
                    .statusCode(200)
                    .body("resources.manifests.total", CoreMatchers.is(2))
                    .body("resources.generations.total", CoreMatchers.is(2))
                    .body("resources.generations.inProgress", CoreMatchers.is(0))
                    .body("uptime", CoreMatchers.isA(String.class))
                    .body("uptimeMillis", CoreMatchers.isA(Integer.class))
                    .body("version", CoreMatchers.isA(String.class))
                    .body("appEnv", CoreMatchers.is("prod"))
                    .body("hostname", CoreMatchers.is("localhost"))
                    .body("deployment.target", CoreMatchers.is("aws"))
                    .body("deployment.type", CoreMatchers.is("preprod"))
                    .body("deployment.zone", CoreMatchers.is("us-east-1"))
                    .body("release", CoreMatchers.is("sbomer-abc"));
        }

        @Test
        void testStatsEndpoint() {
            Mockito.when(sbomService.countSboms()).thenReturn(12L);
            Mockito.when(sbomService.countSbomGenerationRequests()).thenReturn(500L);

            RestAssured.given()
                    .when()
                    .get(String.format("/api/%s/stats", apiVersion))
                    .then()
                    .statusCode(200)
                    .body("resources.manifests.total", CoreMatchers.is(12))
                    .body("resources.generations.total", CoreMatchers.is(500));
        }
    }

}
